const Repository = require("../core/repository");
const crypto = require("crypto");
const axios = require("axios");

class AccountRepository extends Repository {
  constructor(client) {
    super(client);
    // Default max retries for any request
    this.maxRetries = 3;
  }

  /**
   * Generic request wrapper with retry and debug logging
   * @param {Function} requestFn - async function performing request
   * @param {number} retries - current retry count
   */
  async requestWithRetry(requestFn, retries = 0) {
    try {
      if (process.env.DEBUG) console.log(`[DEBUG] Attempt #${retries + 1}`);
      const result = await requestFn();
      return result;
    } catch (error) {
      const shouldRetry =
        (error.data?.error_type === "server_error" ||
          error.data?.error_type === "rate_limited") &&
        retries < this.maxRetries;

      if (shouldRetry) {
        const delay = 1000 * (retries + 1);
        if (process.env.DEBUG)
          console.log(
            `[DEBUG] Retrying after ${delay}ms due to ${error.data?.error_type}`,
          );
        await new Promise((resolve) => setTimeout(resolve, delay));
        return this.requestWithRetry(requestFn, retries + 1);
      }

      throw error;
    }
  }

  /**
   * Login with username/password
   * @param {Object|string} credentialsOrUsername - { username, password } or username string
   * @param {string} passwordArg - password (if first arg is username string)
   */
  async login(credentialsOrUsername, passwordArg) {
    let username, password;

    // Support both object and separate parameters
    if (
      typeof credentialsOrUsername === "object" &&
      credentialsOrUsername !== null
    ) {
      username = credentialsOrUsername.username;
      password = credentialsOrUsername.password;
    } else {
      username = credentialsOrUsername;
      password = passwordArg;
    }

    if (!username || !password) {
      throw new Error("Username and password are required");
    }

    // Use web login flow (more reliable than mobile API encryption)
    return this.webLogin(username, password);
  }

  /**
   * Web-based login flow that works with Instagram's current authentication
   */
  async webLogin(username, password) {
    const WEB_UA =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

    // Step 1: Get CSRF token from Instagram web
    const preRes = await axios({
      method: "GET",
      url: "https://www.instagram.com/accounts/login/",
      headers: { "User-Agent": WEB_UA },
      validateStatus: () => true,
    });

    const preCookies = preRes.headers["set-cookie"] || [];
    const csrfMatch = preCookies.find((c) => c.startsWith("csrftoken="));
    const csrfToken = csrfMatch ? csrfMatch.split("=")[1].split(";")[0] : "";
    const cookieStr = preCookies.map((c) => c.split(";")[0]).join("; ");

    // Step 2: Login via web API
    const time = Math.floor(Date.now() / 1000);
    const loginRes = await axios({
      method: "POST",
      url: "https://www.instagram.com/api/v1/web/accounts/login/ajax/",
      headers: {
        "User-Agent": WEB_UA,
        "X-CSRFToken": csrfToken,
        "X-Instagram-AJAX": "1",
        "X-IG-App-ID": "936619743392459",
        "X-Requested-With": "XMLHttpRequest",
        Referer: "https://www.instagram.com/accounts/login/",
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookieStr,
      },
      data: `username=${encodeURIComponent(username)}&enc_password=${encodeURIComponent("#PWD_INSTAGRAM_BROWSER:0:" + time + ":" + password)}&queryParams=%7B%7D&optIntoOneTap=false`,
      validateStatus: () => true,
    });

    const body = loginRes.data;

    if (body.two_factor_required) {
      const err = new Error("Two factor authentication required");
      err.name = "IgLoginTwoFactorRequiredError";
      throw err;
    }
    if (!body.authenticated) {
      const err = new Error(
        body.message || "Login failed - invalid credentials",
      );
      err.name = "IgLoginBadPasswordError";
      err.data = body;
      throw err;
    }

    // Step 3: Transfer web session cookies to client state
    const loginCookies = loginRes.headers["set-cookie"] || [];
    const allCookies = [...preCookies, ...loginCookies];
    for (const cookieString of allCookies) {
      try {
        this.client.state.cookieJar.setCookieSync(
          cookieString,
          "https://i.instagram.com/",
        );
      } catch (e) {}
      try {
        this.client.state.cookieJar.setCookieSync(
          cookieString,
          "https://www.instagram.com/",
        );
      } catch (e) {}
    }

    // Step 4: Now use the mobile API to get full user data
    // First sync experiments to get proper mobile session
    try {
      await this.syncLoginExperiments();
    } catch (e) {}

    // Get current user info via mobile API
    try {
      const userInfo = await this.currentUser();
      return userInfo;
    } catch (e) {
      // Return basic info from web login
      return { pk: body.userId, username: username };
    }
  }

  /**
   * Logout user
   */
  async logout() {
    return this.requestWithRetry(async () => {
      const response = await this.client.request.send({
        method: "POST",
        url: "/api/v1/accounts/logout/",
        form: this.client.request.sign({
          _csrftoken: this.client.state.cookieCsrfToken,
          _uuid: this.client.state.uuid,
        }),
      });
      return response.body;
    });
  }

  /**
   * Get current user
   */
  async currentUser() {
    return this.requestWithRetry(async () => {
      const response = await this.client.request.send({
        method: "GET",
        url: "/api/v1/accounts/current_user/",
        qs: { edit: true },
      });
      return response.body;
    });
  }

  /**
   * Sync login experiments (required for encryption keys)
   */
  async syncLoginExperiments() {
    return this.requestWithRetry(async () => {
      const response = await this.client.request.send({
        method: "POST",
        url: "/api/v1/qe/sync/",
        form: this.client.request.sign({
          _csrftoken: this.client.state.cookieCsrfToken,
          id: this.client.state.uuid,
          server_config_retrieval: "1",
          experiments: this.client.state.constants.LOGIN_EXPERIMENTS,
        }),
      });
      return response.body;
    });
  }

  /**
   * Create jazoest string from input
   * @param {string} input
   */
  static createJazoest(input) {
    const buf = Buffer.from(input, "ascii");
    let sum = 0;
    for (let i = 0; i < buf.byteLength; i++) {
      sum += buf.readUInt8(i);
    }
    return `2${sum}`;
  }

  /**
   * Encrypt password using Instagram's password encryption
   * @param {string} password
   */
  encryptPassword(password) {
    if (!this.client.state.passwordEncryptionPubKey) {
      console.warn(
        "[WARN] Password encryption key missing. Using plaintext password.",
      );
      return {
        time: Math.floor(Date.now() / 1000).toString(),
        encrypted: password,
      };
    }

    const randKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    const rsaEncrypted = crypto.publicEncrypt(
      {
        key: Buffer.from(
          this.client.state.passwordEncryptionPubKey,
          "base64",
        ).toString(),
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      randKey,
    );

    const cipher = crypto.createCipheriv("aes-256-gcm", randKey, iv);
    const time = Math.floor(Date.now() / 1000).toString();
    cipher.setAAD(Buffer.from(time));

    const aesEncrypted = Buffer.concat([
      cipher.update(password, "utf8"),
      cipher.final(),
    ]);
    const sizeBuffer = Buffer.alloc(2, 0);
    sizeBuffer.writeInt16LE(rsaEncrypted.byteLength, 0);
    const authTag = cipher.getAuthTag();

    if (process.env.DEBUG) {
      console.log(
        `[DEBUG] AES length: ${aesEncrypted.length}, RSA length: ${rsaEncrypted.length}`,
      );
    }

    return {
      time,
      encrypted: Buffer.concat([
        Buffer.from([1, this.client.state.passwordEncryptionKeyId || 0]),
        iv,
        sizeBuffer,
        rsaEncrypted,
        authTag,
        aesEncrypted,
      ]).toString("base64"),
    };
  }

  /**
   * Send password recovery request to Instagram via email
   * @param {string} query - Username, email, or phone number
   */
  async sendRecoveryFlowEmail(query) {
    return this.requestWithRetry(async () => {
      const response = await this.client.request.send({
        url: "/api/v1/accounts/send_recovery_flow_email/",
        method: "POST",
        form: this.client.request.sign({
          _csrftoken: this.client.state.cookieCsrfToken,
          adid: "",
          guid: this.client.state.uuid,
          device_id: this.client.state.deviceId,
          query,
        }),
      });
      return response.body;
    });
  }

  /**
   * Send password recovery request to Instagram via SMS
   * @param {string} query - Username, email, or phone number
   */
  async sendRecoveryFlowSms(query) {
    return this.requestWithRetry(async () => {
      const response = await this.client.request.send({
        url: "/api/v1/accounts/send_recovery_flow_sms/",
        method: "POST",
        form: this.client.request.sign({
          _csrftoken: this.client.state.cookieCsrfToken,
          adid: "",
          guid: this.client.state.uuid,
          device_id: this.client.state.deviceId,
          query,
        }),
      });
      return response.body;
    });
  }
}

module.exports = AccountRepository;
