const {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
} = require("amazon-cognito-identity-js");
const CryptoJS = require("crypto-js");
const jwtDecode = require("jwt-decode");

const cognitoAuth = async (authData) => {
  const {
    Username: E2E_USERNAME,
    Password: E2E_PASSWORD,
    Region,
    ClientId: COGNITO_CLIENT_ID,
    UserPoolId: COGNITO_USER_POOL_ID,
    TokenType,
    ClientSecret,
  } = authData;
  var poolData = {
    UserPoolId: COGNITO_USER_POOL_ID,
    ClientId: COGNITO_CLIENT_ID,
  };
  const userPool = new CognitoUserPool(poolData);
  const cognitoUserData = {
    Username: E2E_USERNAME,
    Pool: userPool,
  };
  const cognitoUser = new CognitoUser(cognitoUserData);
  cognitoUser.setAuthenticationFlowType("USER_SRP_AUTH");
  const authDetails = new AuthenticationDetails({
    Username: E2E_USERNAME,
    Password: E2E_PASSWORD,
  });
  const authUser = await new Promise((resolve, reject) => {
    cognitoUser.authenticateUser(authDetails, {
      onSuccess: resolve,
      onFailure: reject,
    });
  });
  if (TokenType === "id") return authUser.getIdToken().getJwtToken();
  return authUser.getAccessToken().getJwtToken();
};

// Validate if the token has expired
const validToken = (token) => {
  const now = Date.now().valueOf() / 1000;
  try {
    const data = jwtDecode(token);
    if (typeof data.exp !== "undefined" && data.exp < now) {
      return false;
    }
    if (typeof data.nbf !== "undefined" && data.nbf > now) {
      return false;
    }
    return true;
  } catch (err) {
    return false;
  }
};

// Encode our token
const base64url = (source) => {
  var encodedSource = CryptoJS.enc.Base64.stringify(source);
  encodedSource = encodedSource.replace(/=+$/, "");
  encodedSource = encodedSource.replace(/\+/g, "-");
  encodedSource = encodedSource.replace(/\//g, "_");
  return encodedSource;
};
// Create a fake token to keep in store, so we don't query for same wrong values
const errorToken = (error) => {
  const header = {
    alg: "HS256",
    typ: "JWT",
  };
  const stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header));
  const encodedHeader = base64url(stringifiedHeader);
  // If error we keep it for 1 min
  const exp = Date.now().valueOf() / 1000 + 60;
  const data = {
    error,
    exp,
  };
  const stringifiedData = CryptoJS.enc.Utf8.parse(JSON.stringify(data));
  const encodedData = base64url(stringifiedData);
  return encodedHeader + "." + encodedData;
};

// Main run function
const run = async (
  context,
  Username,
  Password,
  Region,
  ClientId,
  UserPoolId,
  TokenType,
  ClientSecret
) => {
  if (!Username) {
    throw new Error("Username attribute is required");
  }
  if (!Password) {
    throw new Error("Password attribute is required");
  }
  if (!Region) {
    throw new Error("Region attribute is required");
  }
  if (!ClientId) {
    throw new Error("ClientId attribute is required");
  }
  if (!UserPoolId) {
    throw new Error("UserPoolId attribute is required");
  }
  if (!TokenType) {
    TokenType = "access";
  }

  const key = [
    Username,
    Password,
    Region,
    ClientId,
    UserPoolId,
    TokenType,
    ClientSecret,
  ].join("::");
  const token = await context.store.getItem(key);
  if (token && validToken(token)) {
    if (jwtDecode(token).error) {
      // Display error
      return jwtDecode(token).error;
    }
    // JWT token is still valid, reuse it
    return token;
  } else {
    // Compute a new token
    try {
      const token = await cognitoAuth({
        Username,
        Password,
        Region,
        ClientId,
        UserPoolId,
        TokenType,
        ClientSecret,
      });
      await context.store.setItem(key, token);
      return token;
    } catch (error) {
      // To keep thing simple we create a fake JWT token with error message
      const token = errorToken(error.message);
      await context.store.setItem(key, token);
      return error.message;
    }
  }
};

module.exports.templateTags = [
  {
    name: "AwsCognitoToken",
    displayName: "AWS Cognito Token",
    description: "Plugin for Insomnia to provide Cognito JWT token from AWS",
    args: [
      {
        displayName: "Username",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "Password",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "Region",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "ClientId",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "UserPoolId",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "TokenType",
        type: "enum",
        defaultValue: "access",
        options: [
          {
            displayName: "access",
            value: "access",
          },
          {
            displayName: "id",
            value: "id",
          },
          {
            displayName: "Raw Request",
            value: "raw_request",
          },
        ],
      },
      {
        displayName: "ClientSecret",
        type: "string",
      },
    ],
    run,
  },
];

module.exports.run = run;