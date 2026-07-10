import express from "express";

import axios from "axios";

import { v4 as uuidv4 } from "uuid";
import {default as NodeCache } from "node-cache";
import QRCode from "qrcode-svg";

import path from "node:path";

import pino from "pino";
import colada from "pino-colada";

import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { EventEmitter } from 'node:events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ##        #######   ######    ######   ######## ########
// ##       ##     ## ##    ##  ##    ##  ##       ##     ##
// ##       ##     ## ##        ##        ##       ##     ##
// ##       ##     ## ##   #### ##   #### ######   ########
// ##       ##     ## ##    ##  ##    ##  ##       ##   ##
// ##       ##     ## ##    ##  ##    ##  ##       ##    ##
// ########  #######   ######    ######   ######## ##     ##
// Setup the Pino Logger

const logger_stream = {
  formatter: colada(),
  console: (level, msg) => {
    if (level <= 30)
      process.stdout.write(msg);
    else
      process.stderr.write(msg);
  },
  write: function(msg) {
    msg = JSON.parse(msg);
    let level = msg["level"] ?? 30;
    msg = this.formatter(msg);
    if (msg.length > 0) {
      this.console(level, msg);
    }
  },
}

const logger = pino({
  prettifier: colada,
  level: 'trace',
}, logger_stream);

// ######## ##     ## ########  ########  ########  ######   ######
// ##        ##   ##  ##     ## ##     ## ##       ##    ## ##    ##
// ##         ## ##   ##     ## ##     ## ##       ##       ##
// ######      ###    ########  ########  ######    ######   ######
// ##         ## ##   ##        ##   ##   ##             ##       ##
// ##        ##   ##  ##        ##    ##  ##       ##    ## ##    ##
// ######## ##     ## ##        ##     ## ########  ######   ######
// Setup the Express app

const app = express();
app.set("views", path.join(__dirname, "templates"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.json());
app.use(express.static("public"));

const events = new EventEmitter();
const exchangeCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });
const presentationCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";
const API_KEY = process.env.API_KEY;
const AUTHSERVER_NGROK_URL = process.env.AUTHSERVER_NGROK_URL;
const DEMO_APP_NGROK_URL = process.env.DEMO_APP_NGROK_URL;
const ISSUER_NGROK_URL = process.env.ISSUER_NGROK_URL;
const ADMIN_MANAGE_AUTH_TOKEN = process.env.ADMIN_MANAGE_AUTH_TOKEN;
const TENANT_SECRET = process.env.TENANT_SECRET;

//certificate and private key to import for mDL issuance
//expires 2036, private_key is PEM base64 encoded PKCS #8.
//TODO the certifciate does not work for verification as a trust anchor - IACA extensions are missing.
const certificate_pem = "-----BEGIN CERTIFICATE-----\nMIIB1DCCAXmgAwIBAgIIdNRHwTfOGwcwCgYIKoZIzj0EAwIwDTELMAkGA1UEBhMC\nQ0EwHhcNMjYwNDEzMTkyNDAwWhcNMzYwNDEzMTkyNDAwWjANMQswCQYDVQQGEwJD\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNKdpd24SPAyNLWNd4J/hlEU5awn\nh26s4sQnJ6cy5tzF92eoNCoz/RKeUD2pCUStdJhN3qYnXgnMbDqLlGIt0bmjgcIw\ngb8wEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUQHLNvJUIYoRcUOiu5qhb\nvaxt4UgwDgYDVR0PAQH/BAQDAgEGMCIGA1UdEgQbMBmGF21haWx0bzp1c2VyQGV4\nYW1wbGUuY29tMCMGA1UdHwQcMBowGKAWoBSGEmh0dHA6Ly9leGFtcGxlLmNvbTAR\nBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0\nZTAKBggqhkjOPQQDAgNJADBGAiEA0zfq5zFY1hz9E//K9n/JlcVDZ+WN1bTduq8u\n/MXtoPkCIQCQw3KbsNB9e/2yskidmuJe5CdFK3VvZpw0SC8IsG2H5A==\n-----END CERTIFICATE-----\n";
const private_key_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6Al13xaXxheg2tsc\nIQEdUKWRqaCAdcHCfPxw6+yTufWhRANCAATSnaXduEjwMjS1jXeCf4ZRFOWsJ4du\nrOLEJyenMubcxfdnqDQqM/0SnlA9qQlErXSYTd6mJ14JzGw6i5RiLdG5\n-----END PRIVATE KEY-----\n";
let jwtVcSupportedCredCreated = false;
let sdJwtSupportedCredCreated = false;
let mdocSupportedCredCreated = false;
let photoIdSupportedCredCreated = false;
let sdJwtStatusListCreated = false;
let jwtStatusListCreated = false;
let jwtVcSupportedCredID = "";
let sdJwtSupportedCredID = "";
let mdocSupportedCredID = "";
let photoIdSupportedCredID = "";
let jwtStatusListID = "";
let sdJwtStatusListID = "";


//    ###     ######     ###            ########  ##    ##
//   ## ##   ##    ##   ## ##           ##     ##  ##  ##
//  ##   ##  ##        ##   ##          ##     ##   ####
// ##     ## ##       ##     ## ####### ########     ##
// ######### ##       #########         ##           ##
// ##     ## ##    ## ##     ##         ##           ##
// ##     ##  ######  ##     ##         ##           ##
// ACA-Py related controller helper functions

// Begin Issue JWT Credential Flow
async function issue_jwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, email } = req.body

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/jwt`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      cryptographic_binding_methods_supported: ["did"],
      credential_signing_alg_values_supported: ["ES256"],
      format: "jwt_vc_json",
      id: "UniversityDegreeCredential",
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ["ES256"]
        }
      },
      credential_definition: {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
        ],
        type: [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ],
      },
      credential_metadata: {
        display: [
          {
            name: "University Credential",
            locale: "en-US",
            logo: {
             url: "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
              alt_text: "a square logo of a university",
            },
            background_color: "#12107c",
            text_color: "#FFFFFF",
          },
        ],
        claims: [
          {
             path: [
              "degree"
             ],
             display: [
                {
                  name: "Degree",
                  locale: "en-US",
                },
             ],
          },
          {
            path: [
              "given_name"
            ],
            display: [
              {
                name: "Given Name",
                locale: "en-US",
              },
            ],
          },
          {
            path: [
              "gpa"
            ],
            display: [
              {
                name: "GPA Score",
                locale: "en-US",
              },
            ],
          },
          {
            path: [
              "last_name"
            ],
            display: [
              {
                name: "Surname",
                locale: "en-US",
              },
            ],
          },
        ],
      },
    }),
  };

  if (!jwtVcSupportedCredCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    jwtVcSupportedCredID = supportedCredentialData.supported_cred_id;
    jwtVcSupportedCredCreated = true;
  }

   logger.info(jwtVcSupportedCredID);

  // Create bitstring status list Configuration
  const statusListCreateUrl = `${API_BASE_URL}/status-list/defs`;
  const statusListCreateOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      issuer_did: issuerDID,
      list_size: 131072,
      list_type: "w3c",
      shard_size: 131072,
      status_message: [
        {
            status: "0x00",
            message: "active"
        },
        {
            status: "0x01",
            message: "inactive"
        },
    ],
    status_purpose: "revocation",
    status_size: 1,
    supported_cred_id: jwtVcSupportedCredID,
    verification_method: issuerDID+"#0"
    })
  };

  if (!jwtStatusListCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Status List Request to: ${statusListCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: statusListCreateOptions});
    const statusListResponse = await fetchApiData(statusListCreateUrl, statusListCreateOptions);
    jwtStatusListID = statusListResponse.id;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created Status List ID: ${jwtStatusListID}`});
    jwtStatusListCreated = true;
  };

  // Create Credential Exchange records
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const exchangeCreateOptions = {
    credential_subject: { id: req.body.registrationId, first_name: firstName, last_name: lastName, email },
    did: issuerDID,
    verification_method: issuerDID+"#0",
    supported_cred_id: jwtVcSupportedCredID,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  // Get Credential Offer information
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = {
    user_pin_required: false,
    exchange_id: exchangeId,
  };
  const credentialOfferOptions = {
    params: queryParams,
    headers: headers,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;

  // Generate QRCode and send it to the browser via HTMX events
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  
  let qrcode;
  if (credentialOffer.hasOwnProperty("credential_offer")) {
    // credential offer is passed by value
    qrcode = credentialOffer.credential_offer
  } else {
    // credential offer is passed by reference, and the wallet must dereference it using the
    // /oid4vci/dereference-credential-offer endpoint
    qrcode = credentialOffer.credential_offer_uri
  }

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did: issuerDID, jwtVcSupportedCredID, registrationId: req.body.registrationId });

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}


// Begin Issue SD-JWT Credential Flow
async function issue_sdjwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, age: ageString } = req.body
  const age = parseInt(ageString);

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/sd-jwt`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "vc+sd-jwt",
      id: "IDCard",
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: [
            "ES256"
          ]
        }
      },
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256K"],
      vct: "ExampleIDCard",
      sd_list: [
          "/given_name",
          "/family_name",
          "/age_is_over_12",
          "/age_is_over_14",
          "/age_is_over_16",
          "/age_is_over_18",
          "/age_is_over_21",
          "/age_is_over_65"
        ],
      credential_metadata: {  
        display: [
          {
            "name": "ID Card",
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
          "path": ["given_name"],
          "display": [
            {
              "name": "Given Name",
              "locale": "en-US"
            }
          ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Family Name",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["something_nested", "key1", "key2", "key3"],
            "display": [
              {
                "name": "Something Nested",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_12"],
            "display": [
              {
                "name": "Age 12 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_14"],
            "display": [
              {
                "name": "Age 14 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_16"],
            "display": [
              {
                "name": "Age 16 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_18"],
            "display": [
              {
                "name": "Age 18 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_21"],
            "display": [
              {
                "name": "Age 21 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_65"],
            "display": [
              {
                "name": "Age 65 or Over",
                "locale": "en-US"
              }
            ]
          }
        ],
      }
    }),
  };

  if (!sdJwtSupportedCredCreated){

    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    sdJwtSupportedCredID = supportedCredentialData.supported_cred_id;
    sdJwtSupportedCredCreated = true;
  }

  logger.info(sdJwtSupportedCredID);

  // Create IETF Token status list Configuration
  const statusListCreateUrl = `${API_BASE_URL}/status-list/defs`;
  const statusListCreateOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      issuer_did: issuerDID,
      list_size: 131072,
      list_type: "ietf",
      shard_size: 131072,
      status_message: [
        {
            status: "0x00",
            message: "active"
        },
        {
            status: "0x01",
            message: "inactive"
        },
    ],
    status_purpose: "revocation",
    status_size: 1,
    supported_cred_id: sdJwtSupportedCredID,
    verification_method: issuerDID+"#0"
    })
  };

  if (!sdJwtStatusListCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Status List Request to: ${statusListCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: statusListCreateOptions});
    const statusListResponse = await fetchApiData(statusListCreateUrl, statusListCreateOptions);
    sdJwtStatusListID = statusListResponse.id;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created Status List ID: ${sdJwtStatusListID}`});
    sdJwtStatusListCreated = true;
  };

  const isRefresh = req.body['is-refresh'] === 'on';
  const refreshId = req.body['refresh-id'];

  const exchangeCreateOptions = {
    did: issuerDID,
    verification_method: issuerDID+"#0",
    supported_cred_id: sdJwtSupportedCredID,
    credential_subject: {
      given_name: firstName,
      family_name: lastName,
      something_nested: {key1: {key2: {key3: "something nested"}}},
      source_document_type: "id_card",
      age_is_over_12: true,
      age_is_over_14: true,
      age_is_over_16: true,
      age_is_over_18: true,
      age_is_over_21: true,
      age_is_over_65: false,
    },
  };
  
  let exchangeId;
  if (isRefresh) {
    const refreshUrl = `${API_BASE_URL}/oid4vci/credential-refresh/${refreshId}`;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Refresh Request to: ${refreshUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
    const exchangeResponse = await axios.patch(refreshUrl, exchangeCreateOptions);
    exchangeId = exchangeResponse.data.exchange_id;
  } else {
    const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
    const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
    exchangeId = exchangeResponse.data.exchange_id;
  }
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  if (!isRefresh) {
    // Get Credential Offer information
    const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
    const queryParams = {
      user_pin_required: false,
      exchange_id: exchangeId,
    };
    const credentialOfferOptions = {
      params: queryParams,
      headers: headers,
    };
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
    const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
    const credentialOffer = offerResponse.data;

    // Generate QRCode and send it to the browser via HTMX events
    logger.info(JSON.stringify(offerResponse.data));
    logger.info(exchangeId);

    let qrcode;
    if (credentialOffer.hasOwnProperty("credential_offer")) {
      // credential offer is passed by value
      qrcode = credentialOffer.credential_offer
    } else {
      // credential offer is passed by reference, and the wallet must dereference it using the
      // /oid4vci/dereference-credential-offer endpoint
      qrcode = credentialOffer.credential_offer_uri
    }

    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
    exchangeCache.set(exchangeId, { exchangeId, credentialOffer, issuerDID, sdJwtSupportedCredID, registrationId: req.body.registrationId });

    // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
  } else {
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Credential Refresh API call was successful."});
  }
}

// Begin Issue mDL (mso_mdoc) Credential Flow
async function issue_mdoc_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received mDL credential data from user."});

  console.log("req.body", req.body);
  const {
    family_name,
    given_name,
    birth_date,
    birth_place,
    sex,
    issue_date,
    expiry_date,
    issuing_authority,
    document_number,
    issuing_country,
    un_distinguishing_sign,
    portrait,
    resident_address,
    resident_city,
    resident_state,
    resident_postal_code,
    resident_country,
  } = req.body;

  const sexInt = parseInt(sex, 10);
  const birthMs = new Date(birth_date).getTime();
  const nowMs = Date.now();
  const ageYears = (nowMs - birthMs) / (365.25 * 24 * 60 * 60 * 1000);
  const age_over_19 = ageYears >= 19;
  const age_over_21 = ageYears >= 21;
  const age_over_65 = ageYears >= 65;

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }

  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/mso-mdoc`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "mso_mdoc",
      id: "org.iso.18013.5.1.mDL",
      doctype: "org.iso.18013.5.1.mDL",
      signing_key_id: mdocKeyId,
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: [
        "ES256"
      ],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: [
            "ES256"
          ]
        }
      },
      "credential_metadata": {
        claims: [
          { path: ["org.iso.18013.5.1", "given_name"], display: [{ name: "Given Name", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "family_name"], display: [{ name: "Family Name", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "birth_date"], display: [{ name: "Birth Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issue_date"], display: [{ name: "Issue Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "expiry_date"], display: [{ name: "Expiry Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issuing_authority"], display: [{ name: "Issuing Authority", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "document_number"], display: [{ name: "Document Number", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issuing_country"], display: [{ name: "Issuing Country", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "un_distinguishing_sign"], display: [{ name: "UN Distinguishing Sign", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "portrait"], display: [{ name: "Portrait", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "age_over_19"], display: [{ name: "Age Over 19", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "age_over_21"], display: [{ name: "Age Over 21", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "age_over_65"], display: [{ name: "Age Over 65", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "birth_place"], display: [{ name: "Birth Place", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "sex"], display: [{ name: "Sex", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "resident_address"], display: [{ name: "Resident Address", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "resident_city"], display: [{ name: "Resident City", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "resident_state"], display: [{ name: "Resident State", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "resident_postal_code"], display: [{ name: "Resident Postal Code", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "resident_country"], display: [{ name: "Resident Country", locale: "en-US" }] }
        ],
        display: [
          {
            name: "Sample Driving License",
            locale: "en-US",
            background_image: {
              uri: "data:image/png;base64,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",
              alt_text: "Driver's License Background"
            }
          }
        ],
      },
    }),
  };

  if (!mdocSupportedCredCreated) {
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    console.log("Creating mDL supported credential", createCredentialSupportedOptions);
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    mdocSupportedCredID = supportedCredentialData.supported_cred_id;
    mdocSupportedCredCreated = true;
  }

  logger.info(mdocSupportedCredID);
  
  // Create credential exchange
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
 
  console.log("FAMILY NAME", family_name);
  const exchangeCreateOptions = {
      supported_cred_id: mdocSupportedCredID,
      credential_subject: {
        "org.iso.18013.5.1": {
          family_name,
          given_name,
          birth_date,
          issue_date,
          expiry_date,
          issuing_country,
          issuing_authority,
          document_number,
          portrait,
          un_distinguishing_sign,
          age_over_19,
          age_over_21,
          age_over_65,
          birth_place,
          sex: sexInt,
          resident_address,
          resident_city,
          resident_state,
          resident_postal_code,
          resident_country,
        }
      },
      verification_method: issuerDID + "#0",
  };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});
  
  
  // Get credential offer and emit QR code as in other flows
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = {
    exchange_id: exchangeId,
    user_pin_required: false,
  };

  const credentialOfferOptions = {
    params: queryParams,
    headers: headers,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;
  
  let qrcode;
  if (credentialOffer.credential_offer) {
    qrcode = credentialOffer.credential_offer;
  } else {
    qrcode = credentialOffer.credential_offer_uri;
  } 
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, mdocSupportedCredID, registrationId: req.body.registrationId });

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}

// Begin Issue Photo ID (mso_mdoc org.iso.23220.1.mID) Credential Flow
async function issue_photoid_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received Photo ID credential data from user."});

  console.log("req.body", req.body);
  const {
    family_name,
    given_name,
    birth_date,
    birthplace,
    sex,
    height,
    weight,
    nationality,
    issue_date,
    expiry_date,
    issuing_authority_unicode,
    issuing_country,
    issuing_subdivision,
    document_number,
    document_type,
    portrait,
    resident_address,
    resident_city,
    resident_state,
    resident_postal_code,
    resident_country,
  } = req.body;

  const sexInt = sex ? parseInt(sex, 10) : undefined;
  const birthMs = new Date(birth_date).getTime();
  const nowMs = Date.now();
  const ageYears = (nowMs - birthMs) / (365.25 * 24 * 60 * 60 * 1000);
  const age_over_18 = req.body.age_over_18 === "true" || ageYears >= 18;
  const age_over_21 = req.body.age_over_21 === "true" || ageYears >= 21;

  const headers = { accept: "application/json" };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] = API_KEY;
  }

  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/mso-mdoc`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "mso_mdoc",
      id: "org.iso.23220.1.mID",
      doctype: "org.iso.23220.1.mID",
      signing_key_id: photoIdKeyId,
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256"],
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"] }
      },
      credential_metadata: {
        claims: [
          { path: ["org.iso.23220.1", "family_name"],             display: [{ name: "Family Name",        locale: "en-US" }] },
          { path: ["org.iso.23220.1", "given_name"],              display: [{ name: "Given Name",         locale: "en-US" }] },
          { path: ["org.iso.23220.1", "birth_date"],              display: [{ name: "Birth Date",         locale: "en-US" }] },
          { path: ["org.iso.23220.1", "issue_date"],              display: [{ name: "Issue Date",         locale: "en-US" }] },
          { path: ["org.iso.23220.1", "expiry_date"],             display: [{ name: "Expiry Date",        locale: "en-US" }] },
          { path: ["org.iso.23220.1", "issuing_authority_unicode"], display: [{ name: "Issuing Authority",locale: "en-US" }] },
          { path: ["org.iso.23220.1", "document_number"],         display: [{ name: "Document Number",   locale: "en-US" }] },
          { path: ["org.iso.23220.1", "issuing_country"],         display: [{ name: "Issuing Country",   locale: "en-US" }] },
          { path: ["org.iso.23220.1", "portrait"],                display: [{ name: "Portrait",          locale: "en-US" }] },
          { path: ["org.iso.23220.1", "sex"],                     display: [{ name: "Sex",               locale: "en-US" }] },
          { path: ["org.iso.23220.1", "birthplace"],              display: [{ name: "Birthplace",        locale: "en-US" }] },
          { path: ["org.iso.23220.1", "nationality"],             display: [{ name: "Nationality",       locale: "en-US" }] },
          { path: ["org.iso.23220.1", "resident_address"],        display: [{ name: "Resident Address",  locale: "en-US" }] },
          { path: ["org.iso.23220.1", "resident_city"],           display: [{ name: "Resident City",     locale: "en-US" }] },
          { path: ["org.iso.23220.1", "resident_state"],          display: [{ name: "Resident State",    locale: "en-US" }] },
          { path: ["org.iso.23220.1", "resident_postal_code"],    display: [{ name: "Resident Postal Code", locale: "en-US" }] },
          { path: ["org.iso.23220.1", "resident_country"],        display: [{ name: "Resident Country",  locale: "en-US" }] },
          { path: ["org.iso.23220.1", "age_over_18"],             display: [{ name: "Age Over 18",       locale: "en-US" }] },
          { path: ["org.iso.23220.1", "age_over_21"],             display: [{ name: "Age Over 21",       locale: "en-US" }] },
        ],
        display: [
          {
            name: "Photo ID",
            locale: "en-US",
            background_color: "#1a3a5c",
            text_color: "#FFFFFF",
          }
        ],
      },
    }),
  };

  if (!photoIdSupportedCredCreated) {
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    console.log("Creating Photo ID supported credential", createCredentialSupportedOptions);
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    photoIdSupportedCredID = supportedCredentialData.supported_cred_id;
    photoIdSupportedCredCreated = true;
  }

  logger.info(photoIdSupportedCredID);

  // Build credential_subject — omit optional fields when blank
  const photoidSubject = {
    family_name,
    given_name,
    birth_date,
    portrait,
    issue_date,
    expiry_date,
    issuing_country,
    issuing_authority_unicode,
    document_number,
    ...(sexInt !== undefined && !isNaN(sexInt) ? { sex: sexInt } : {}),
    ...(birthplace ? { birthplace } : {}),
    ...(height ? { height: parseInt(height, 10) } : {}),
    ...(weight ? { weight: parseInt(weight, 10) } : {}),
    ...(nationality ? { nationality } : {}),
    ...(resident_address ? { resident_address } : {}),
    ...(resident_city ? { resident_city } : {}),
    ...(resident_state ? { resident_state } : {}),
    ...(resident_postal_code ? { resident_postal_code } : {}),
    ...(resident_country ? { resident_country } : {}),
    ...(issuing_subdivision ? { issuing_subdivision } : {}),
    ...(document_type ? { document_type } : {}),
    age_over_18,
    age_over_21,
  };

  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const exchangeCreateOptions = {
    supported_cred_id: photoIdSupportedCredID,
    credential_subject: {
      "org.iso.23220.1": photoidSubject,
    },
    verification_method: issuerDID + "#0",
  };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});

  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions);
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});

  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = { exchange_id: exchangeId, user_pin_required: false };
  const credentialOfferOptions = { params: queryParams, headers };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});

  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;
  const qrcode = credentialOffer.credential_offer || credentialOffer.credential_offer_uri;

  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, photoIdSupportedCredID, registrationId: req.body.registrationId });

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}

// Begin JWT VC JSON Presentation Flow
async function create_jwt_vc_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "format": {
      "jwt_vc_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vc": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp": {
        "alg": [
          "ES256"
        ]
      }
    },
    "input_descriptors": [
      {
        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "fields": [
            {
              "name": "name",
              "path": [
                "$.vc.credentialSubject.first_name",
                "$.credentialSubject.first_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            },
            {
              "name": "lastname",
              "path": [
                "$.vc.credentialSubject.last_name",
                "$.credentialSubject.last_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            }
          ]
        }
      }
    ]
  }
  };

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "jwt_vc": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vc_json": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp_json": { "alg": [ "ES256", "EdDSA" ] }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// Begin SD-JWT Presentation Flow
async function create_sd_jwt_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "input_descriptors": [
      {
        "format": {
          "vc+sd-jwt": {}
        },
        "id": "ID Card",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "limit_disclosure": "required",
          "fields": [
            {
              "path": [
                "$.vct"
              ],
              "filter": {
                "type": "string"
              }
            },
            {
              "path": [
                "$.family_name"
              ]
            },
            {
              "path": [
                "$.given_name"
              ]
            },
            {
              "path": [
                "$.something_nested.key1.key2.key3"
              ]
            },
          ]
        }
      }
    ]
  }};

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "vc+sd-jwt": {
            "sd-jwt_alg_values": [
                "ES256",
                "ES384"
            ],
            "kb-jwt_alg_values": [
                "ES256",
                "ES384"
            ]
        }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// Begin mDOC Presentation Flow (DCQL)
async function create_mdoc_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  // Create DCQL Query for mDL
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DCQL Query for mDL."});
  const dcqlQueryUrl = `${API_BASE_URL}/oid4vp/dcql/queries`;
  const dcqlQueryOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      credentials: [
        {
          id: "mDL",
          format: "mso_mdoc",
          meta: {
            doctype_value: "org.iso.18013.5.1.mDL"
          },
          claims: [
            { namespace: "org.iso.18013.5.1", claim_name: "family_name" },
            { namespace: "org.iso.18013.5.1", claim_name: "given_name" },
            { namespace: "org.iso.18013.5.1", claim_name: "document_number" },
            { namespace: "org.iso.18013.5.1", claim_name: "issuing_country" },
            { namespace: "org.iso.18013.5.1", claim_name: "expiry_date" },
          ],
        }
      ]
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting DCQL Query to: ${dcqlQueryUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: dcqlQueryOptions});
  const dcqlQueryData = await fetchApiData(dcqlQueryUrl, dcqlQueryOptions);
  const dcqlQueryId = dcqlQueryData.dcql_query_id;
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created DCQL Query ID: ${dcqlQueryId}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcqlQueryData});

  // Create Presentation Request using the DCQL query
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      dcql_query_id: dcqlQueryId,
      vp_formats: {
        mso_mdoc: {
          alg: ["ES256"]
        }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(dcqlQueryId, { dcqlQueryData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);
}

// DC-API Presentation Flows
// These mirror the OID4VP flows above but use the W3C Digital Credentials API
// (navigator.credentials.get) instead of a QR code.  The browser mediates
// wallet selection; the wallet response is forwarded here for verification.

async function init_jwt_dcapi_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) commonHeaders["X-API-KEY"] = API_KEY;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "format": {
      "jwt_vc_json": { "alg": ["ES256"] },
      "jwt_vp_json": { "alg": ["ES256"] },
      "jwt_vc":      { "alg": ["ES256"] },
      "jwt_vp":      { "alg": ["ES256"] }
    },
    "input_descriptors": [
      {
        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "fields": [
            { "name": "name",     "path": ["$.vc.credentialSubject.first_name", "$.credentialSubject.first_name"], "filter": {"type": "string", "pattern": "^.{1,64}$"} },
            { "name": "lastname", "path": ["$.vc.credentialSubject.last_name",  "$.credentialSubject.last_name"],  "filter": {"type": "string", "pattern": "^.{1,64}$"} }
          ]
        }
      }
    ]
  }};

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  const presentationDefinitionData = await fetchApiData(presentationDefinitionUrl, {
    method: "POST", headers: commonHeaders, body: JSON.stringify(presentationDefinition),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});

  const dcApiRequestUrl = `${API_BASE_URL}/oid4vp/dc-api/request`;
  const dcApiRequestBody = {
    pres_def_id: presentationDefinitionData.pres_def_id,
    vp_formats: {
      "jwt_vc": { "alg": ["ES256", "EdDSA"] },
      "jwt_vp": { "alg": ["ES256", "EdDSA"] },
      "jwt_vc_json": { "alg": ["ES256", "EdDSA"] },
      "jwt_vp_json": { "alg": ["ES256", "EdDSA"] }
    },
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DC-API request."});
  const dcApiData = await fetchApiData(dcApiRequestUrl, {
    method: "POST", headers: commonHeaders, body: JSON.stringify(dcApiRequestBody),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `DC-API request created. Presentation ID: ${dcApiData.presentation_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcApiData});

  presentationCache.set(presentationDefinitionData.pres_def_id, {
    presentationDefinitionData,
    presentationId,
  });

  res.setHeader("Content-Type", "application/json");
  res.json({
    acapy_presentation_id: dcApiData.presentation_id,
    nonce:      dcApiData.nonce,
    pres_def:   dcApiData.pres_def,
    vp_formats: dcApiData.vp_formats,
  });
}

async function init_sdjwt_dcapi_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) commonHeaders["X-API-KEY"] = API_KEY;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  // Create DCQL query for SD-JWT credential
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DCQL Query for SD-JWT."});
  const dcqlQueryUrl = `${API_BASE_URL}/oid4vp/dcql/queries`;
  const dcqlQueryData = await fetchApiData(dcqlQueryUrl, {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      credentials: [
        {
          id: "profile",
          format: "vc+sd-jwt",
          claims: [
            { path: ["vct"] },
            { path: ["family_name"] },
            { path: ["given_name"] },
          ],
        }
      ]
    }),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created DCQL Query ID: ${dcqlQueryData.dcql_query_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcqlQueryData});

  const dcApiRequestUrl = `${API_BASE_URL}/oid4vp/dc-api/request`;
  const dcApiRequestBody = {
    dcql_query_id: dcqlQueryData.dcql_query_id,
    vp_formats: { "vc+sd-jwt": {}, "kb+jwt": { "alg": ["ES256", "EdDSA"] } },
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DC-API request."});
  const dcApiData = await fetchApiData(dcApiRequestUrl, {
    method: "POST", headers: commonHeaders, body: JSON.stringify(dcApiRequestBody),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `DC-API request created. Presentation ID: ${dcApiData.presentation_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcApiData});

  presentationCache.set(dcqlQueryData.dcql_query_id, {
    dcqlQueryData,
    presentationId,
  });

  const tenantSub = WALLET_ID ? `/tenant/${WALLET_ID}` : "";
  const responseUri = `${ISSUER_NGROK_URL || ""}${tenantSub}/oid4vp/response/${dcApiData.presentation_id}`;

  res.setHeader("Content-Type", "application/json");
  res.json({
    acapy_presentation_id: dcApiData.presentation_id,
    nonce:        dcApiData.nonce,
    client_id:    dcApiData.client_id,
    dcql_query:   dcApiData.dcql_query,
    vp_formats:   dcApiData.vp_formats,
    response_uri: responseUri,
  });
}

async function init_mdoc_dcapi_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) commonHeaders["X-API-KEY"] = API_KEY;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DCQL Query for mDL age_over_21."});
  const dcqlQueryUrl = `${API_BASE_URL}/oid4vp/dcql/queries`;
  const dcqlQueryData = await fetchApiData(dcqlQueryUrl, {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      credentials: [
        {
          id: "mDL",
          format: "mso_mdoc",
          meta: { doctype_value: "org.iso.18013.5.1.mDL" },
          claims: [
            { path: ["org.iso.18013.5.1", "age_over_21"] },
          ],
        }
      ]
    }),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created DCQL Query ID: ${dcqlQueryData.dcql_query_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcqlQueryData});

  const dcApiRequestUrl = `${API_BASE_URL}/oid4vp/dc-api/request`;
  const dcApiRequestBody = {
    dcql_query_id: dcqlQueryData.dcql_query_id,
    vp_formats: { mso_mdoc: { alg: ["ES256"] } },
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DC-API request."});
  const dcApiData = await fetchApiData(dcApiRequestUrl, {
    method: "POST", headers: commonHeaders, body: JSON.stringify(dcApiRequestBody),
  });
  events.emit(`presentation-${presentationId}`, {type: "message", message: `DC-API request created. Presentation ID: ${dcApiData.presentation_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcApiData});

  presentationCache.set(dcqlQueryData.dcql_query_id, {
    dcqlQueryData,
    presentationId,
  });

  const tenantSub = WALLET_ID ? `/tenant/${WALLET_ID}` : "";
  const responseUri = `${ISSUER_NGROK_URL || ""}${tenantSub}/oid4vp/response/${dcApiData.presentation_id}`;
  logger.info("DC-API mdoc response_uri: %s (ISSUER_NGROK_URL=%s)", responseUri, ISSUER_NGROK_URL);

  res.setHeader("Content-Type", "application/json");
  res.json({
    acapy_presentation_id: dcApiData.presentation_id,
    nonce:        dcApiData.nonce,
    client_id:    dcApiData.client_id,
    dcql_query:   dcApiData.dcql_query,
    vp_formats:   dcApiData.vp_formats,
    response_uri: responseUri,
  });
}

// Proxy the DC-API wallet response to ACA-Py's existing verification endpoint.
// The browser POSTs the DigitalCredential.data JSON here; we forward it as
// form data so the backend verification logic is completely unchanged.
async function forward_dcapi_response(req, res) {
  const acapyPresentationId = req.params.presentationId;
  const credData = req.body;

  const formData = new URLSearchParams();
  const vpToken = credData.vp_token;
  formData.append("vp_token",
    typeof vpToken === "string" ? vpToken : JSON.stringify(vpToken)
  );
  if (credData.presentation_submission) {
    const ps = credData.presentation_submission;
    formData.append("presentation_submission",
      typeof ps === "string" ? ps : JSON.stringify(ps)
    );
  }
  if (credData.state) {
    formData.append("state", credData.state);
  }

  // /oid4vp/response/{id} is a PUBLIC route on port 8082, not the admin API (3001).
  // In multitenant mode the path includes /tenant/{wallet_id}.
  const OID4VP_PUBLIC_URL = process.env.OID4VP_PUBLIC_URL || "http://issuer:8082";
  const tenantSubpath = WALLET_ID ? `/tenant/${WALLET_ID}` : "";
  const responseUrl = `${OID4VP_PUBLIC_URL}${tenantSubpath}/oid4vp/response/${acapyPresentationId}`;
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  const result = await fetch(responseUrl, {
    method: "POST",
    headers,
    body: formData.toString(),
  });

  res.status(result.status).json({});
}

// ##     ## ######## ##     ## ##     ##
// ##     ##    ##    ###   ###  ##   ##
// ##     ##    ##    #### ####   ## ##
// #########    ##    ## ### ##    ###
// ##     ##    ##    ##     ##   ## ##
// ##     ##    ##    ##     ##  ##   ##
// ##     ##    ##    ##     ## ##     ##
// ######## ##     ## ######## ##    ## ########  ######
// ##       ##     ## ##       ###   ##    ##    ##    ##
// ##       ##     ## ##       ####  ##    ##    ##
// ######   ##     ## ######   ## ## ##    ##     ######
// ##        ##   ##  ##       ##  ####    ##          ##
// ##         ## ##   ##       ##   ###    ##    ##    ##
// ########    ###    ######## ##    ##    ##     ######

function handleEvents(event_type, req, res) {
  // Send headers indicating that this is an HTMX stream
  // Reflect the requesting origin so cross-origin SSE works when the page is
  // served locally (localhost:3002) but the stream URL uses the ngrok public URL.
  const origin = req.headers.origin || "*";
  res.writeHead(200, {
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "text/event-stream",
  });

  // Reset data
  logger.trace("HTMX Stream started!");
  res.write(`event: debug\ndata: \n\n`);
  res.write(`event: qrcode\ndata: \n\n`);
  let state = ""

  // When we receive an event
  events.on(`${event_type}-${req.params.id}`, (data) => {

    // Send messages verbatim
    if (data.type == "message") {
      res.write(`event: message\ndata: ${data.message}<br />\n\n`);
      return;
    }
    // Debug messages get special formatting
    if (data.type == "debug-message") {
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; ${data.message}: ${JSON.stringify(data.data)}</div>\n\n`);
    }

    // Webhooks mean that ACA-Py sent us data regarding presentations or credential issuance
    if (data.type == "webhook") {

      // Log it for debugging
      logger.trace(JSON.stringify(data, null, 2));
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; Webhook data: ${JSON.stringify(data.data)}</div>\n\n`);

      // Grab the state
      state = data?.data?.state;

      // Handle OID4VP webhooks
      if (data.path == "/webhook/topic/oid4vp/") {
        if (state == "request-retrieved")
          res.write(`event: status\ndata: <div style="text-align: center;">QRCode Scanned, awaiting presentation...</div>\n\n`);
        if (state == "presentation-invalid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentaion verification failed</div>\n\n`);
        if (state == "presentation-valid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentation Verified!</div>\n\n`);
      }

      // Handle OID4VCI webhooks
      if (data.path == "/webhook/topic/oid4vci/") {
        if (state == "issued") {
          res.write(`event: qrcode\ndata: Credential Issued!\n\n`);
          return;
        }
      }
    }
    res.write(`event: debug\ndata: ${JSON.stringify(data)}\n\n`);

    // For OID4VCI: when we receive a "qrcode" message, generate a code and send it to the browser
    if ("qrcode" in data) {
      var qrcode = new QRCode({
        content: data.qrcode,
        padding: 4,
        width: 256,
        height: 256,
        color: "#000000",
        background: "#ffffff",
        ecl: "M",
      });
      logger.debug(data.qrcode);
      res.write(`event: qrcode\ndata: ${qrcode.svg().replace(/\r?\n|\r/g, " ")}\n\n`);
    }
  });

  res.on("close", () => {
    res.end();
  });
}


// ########   #######  ##     ## ######## ########  ######
// ##     ## ##     ## ##     ##    ##    ##       ##    ##
// ##     ## ##     ## ##     ##    ##    ##       ##
// ########  ##     ## ##     ##    ##    ######    ######
// ##   ##   ##     ## ##     ##    ##    ##             ##
// ##    ##  ##     ## ##     ##    ##    ##       ##    ##
// ##     ##  #######   #######     ##    ########  ######
// Express.js Routes

// Render main app
app.get("/", (req, res) => {
  res.render("index", {"registrationId": uuidv4()});
});

const fetchApiData = async (url, options) => {
  const response = await fetch(url, options);
  return await response.json();
};

const token = await fetchApiData(
  `${API_BASE_URL}/multitenancy/wallet`,
  {
    method: "POST",
    headers: {
      accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(
      {
          "label": "Alice",
          "wallet_type": "askar",
      }
    )
  }
);

console.log("_______TOKEN________\n\n\n");
console.log(token);

const WALLET_ID = token.settings["wallet.id"];

// Configure Auth server tenant
async function initializeAuthServer() {
  try {
 
    const AUTHSERVER="http://auth-server:9000"

    const commonHeaders = {
      accept: "application/json",
      "Authorization": "Bearer " + ADMIN_MANAGE_AUTH_TOKEN,
      "Content-Type": "application/json",
    };

    // Create tenant
    const tenantRes = await axios.post(
      `${AUTHSERVER}/admin/tenants`,
      {
        uid: WALLET_ID,
        name: "tenant1",
        active: true,
        notes: "demo tenant"
      },
      { headers: commonHeaders }
    );
    logger.info("Tenant created:", tenantRes.data);

    // Create key for tenant
    const notBefore = new Date();
    const notAfter = new Date(new Date().setFullYear(new Date().getFullYear() + 1));
    console.log("Not before:", notBefore.toISOString());
    console.log("Not after:", notAfter.toISOString());
    

    const keyRes = await axios.post(
      `${AUTHSERVER}/admin/tenants/${WALLET_ID}/keys`,
      {
        alg: "ES256",
        not_before: notBefore.toISOString(),
        not_after: notAfter.toISOString(),
        status: "active"
      },
      { headers: commonHeaders }
    );
    logger.info("Key created:", keyRes.data);

    // Create client for tenant
    const clientRes = await axios.post(
      `${AUTHSERVER}/admin/tenants/${WALLET_ID}/clients`,
      {
        client_id: "client1",
        client_auth_method: "client_secret_basic",
        client_secret: TENANT_SECRET,
      },
      { headers: commonHeaders }
    );
    logger.info("Client created:", clientRes.data);

  } catch (err) {
    logger.error("Auth server initialization failed:", err?.response?.data || err.message);
  }
}

// Configure the Issuer to use the use the Auth server and define issuer metadata.
async function initializeIssuerMetadata() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    const payload = {
      authorization_servers: [
        {
          public_url: `${AUTHSERVER_NGROK_URL}/tenants/${WALLET_ID}`,
          private_url: `http://auth-server:9001/tenants/${WALLET_ID}`,
          auth_type: "client_secret_basic",
          client_credentials: {
            client_id: "client1",
            client_secret: TENANT_SECRET
          }
        }
      ],
      display: [
        {
          name: "Ontario",
          description: "Ontario Issuance Server"
        }
      ]
    };

    const response = await axios.put(
      `${API_BASE_URL}/oid4vci/issuer/configuration`,
      payload,
      { headers: commonHeaders }
    );
    logger.info("Issuer metadata initialized:", response.data);
  } catch (err) {
    logger.error("Issuer metadata initialization failed:", err?.response?.data || err.message);
  }
}

// Create Signing DID. Note that this DID is used to sign both the credential and status list (required by IETF token status list spec)
let issuerDID = null;
async function initializeSigningDid() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    }
    const createDidUrl = `${API_BASE_URL}/did/jwk/create`;
    const createDidOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
        key_type: "p256",
      }),
    };
    logger.info(`Posting Create DID Request to: ${createDidUrl}`);
    logger.info("Request options", createDidOptions);
    const didData = await fetchApiData(createDidUrl, createDidOptions);
    const { did } = didData;
    issuerDID = did;
    logger.info(`Created signing DID: ${issuerDID}`);
  } catch (err) {
    logger.error("Signing DID initialization failed:", err?.response?.data || err.message);
  }
}

// Import Certificate and private key.
let mdocKeyId = null;
let photoIdKeyId = null;
async function initializeMdocSigningKey() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    }
    const createKeyUrl = `${API_BASE_URL}/mso-mdoc/signing-keys/import`;
    const createKeyOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
          "certificate_pem": certificate_pem,
          "private_key_pem": private_key_pem,
          "doctype": "org.iso.18013.5.1.mDL",
          "label": "mDOC signing key",
      }),
    };
    logger.info(`Importing mDOC Signing Key Request to: ${createKeyUrl}`);
    logger.info("Request options", createKeyOptions);
    const keyData = await fetchApiData(createKeyUrl, createKeyOptions);
    mdocKeyId = keyData.id;
    logger.info(`Imported mDOC signing key with ID: ${mdocKeyId}`);

    // Register the certificate as a trust anchor
    const trustAnchorUrl = `${API_BASE_URL}/mso-mdoc/trust-anchors`;
    const trustAnchorOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
        certificate_pem: certificate_pem,
      }),
    };
    logger.info(`Registering mDOC trust anchor to: ${trustAnchorUrl}`);
    const trustAnchorData = await fetchApiData(trustAnchorUrl, trustAnchorOptions);
    logger.info(`Registered mDOC trust anchor:`, trustAnchorData);
  } catch (err) {
    logger.error("mDOC signing key initialization failed:", err?.response?.data || err.message);
  }
}

async function initializePhotoIdSigningKey() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    }
    const createKeyUrl = `${API_BASE_URL}/mso-mdoc/signing-keys/import`;
    const createKeyOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
          "certificate_pem": certificate_pem,
          "private_key_pem": private_key_pem,
          "doctype": "org.iso.23220.1.mID",
          "label": "Photo ID signing key",
      }),
    };
    logger.info(`Importing Photo ID Signing Key to: ${createKeyUrl}`);
    const keyData = await fetchApiData(createKeyUrl, createKeyOptions);
    photoIdKeyId = keyData.id;
    logger.info(`Imported Photo ID signing key with ID: ${photoIdKeyId}`);
  } catch (err) {
    logger.error("Photo ID signing key initialization failed:", err?.response?.data || err.message);
  }
}

await initializeAuthServer();
await initializeIssuerMetadata();
await initializeSigningDid();
await initializeMdocSigningKey();
await initializePhotoIdSigningKey();


// Credential Info route
app.get("/credential-info", async (req, res, next) => {
  try {
    const recordsUrl = `${API_BASE_URL}/oid4vci/exchange/records`;
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    const response = await fetch(recordsUrl, {
      method: "GET",
      headers: commonHeaders
    });
    
    if (response.ok) {
      const records = await response.json();
      res.render("credential-info", { "page": "credential-info", records: JSON.stringify(records, null, 2) });
    } else {
      const respData = await response.text();
      res.status(response.status).send(`<div class="w3-panel w3-pale-red w3-border"><p>Failed to fetch records: ${respData}</p></div>`);
    }
  } catch (err) {
    next(err);
  }
});

// Update Status routes
app.get("/update-status", (req, res) => {
  res.render("update-status-form", {"page": "update-status"});
});
app.get("/update-status/select", (req, res) => {
  res.render(`update-status-fields`, {"page": "update-status"});
});
app.post("/update-status", async (req, res, next) => {
  try {
    const credType = req.body["credential-type"];
    const credId = req.body["credential-id"];
    
    let defId = "";
    if (credType === "jwt") {
      defId = jwtStatusListID;
    } else if (credType === "sdjwt") {
      defId = sdJwtStatusListID;
    } else {
      return res.status(400).send("Invalid credential type for status update.");
    }
    
    if (!defId) {
      return res.status(400).send("Status list for this credential type has not been created yet.");
    }

    const updateUrl = `${API_BASE_URL}/status-list/defs/${defId}/creds/${credId}`;
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    const response = await fetch(updateUrl, {
      method: "PATCH",
      headers: commonHeaders,
      body: JSON.stringify({ status: "1" })
    });
    
    const respData = await response.text();
    
    if (respData.includes("StatusListCred record not found")) {
      res.send(`<div class="w3-panel w3-pale-red w3-border"><p>${respData}</p></div>`);
    } else if (response.ok) {
      res.send(`<div class="w3-panel w3-pale-green w3-border"><p>Status successfully updated for Credential Exchange ID: ${credId}</p></div>`);
    } else {
      res.status(response.status).send(`<div class="w3-panel w3-pale-red w3-border"><p>Failed to update status: ${respData}</p></div>`);
    }
  } catch (err) {
    next(err);
  }
});

// Render Credential Issuance form
app.get("/issue", (req, res) => {
  res.render("issue-form", {"page": "register", "registrationId": uuidv4()});
});
app.get("/issue/select", (req, res) => {
  console.log(req.query);
  res.render(`issue/${req.query["credential-type"]}`, {"page": "register", "registrationId": uuidv4()});
});

app.post("/issue", (req, res, next) => {
  // Begin Credential issuance flow
  //events.on(`${event_type}-${req.params.id}`, (data) => {
    console.log(req.body);
    switch(req.body["credential-type"]) {
      case "jwt":
        issue_jwt_credential(req, res).catch(next);
        break;
      case "sdjwt":
        issue_sdjwt_credential(req, res).catch(next);
        break;
      case "mdoc":
        issue_mdoc_credential(req, res).catch(next);
      break;
      case "photoid":
        issue_photoid_credential(req, res).catch(next);
      break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Issuance page
  app.get("/stream/issue/:id", (req, res) => {
    handleEvents("issuance", req, res);
  });

  app.get("/present/select/:id", (req, res) => {
    console.log(req.query);
    res.render(`present/${req.query["credential-type"]}`, {"page": "register", "presentationId": req.params.id});
  });

  // Render Presentation Exchange form
  app.get("/present", (req, res) => {
    res.render("presentation", {"page": "present", "presentationId": uuidv4()});
  });

  app.get("/present/create/:id", (req, res, next) => {
    // Begin Presentation Exchange flow

    switch(req.query["credential-type"]) {
      case "jwt":
        create_jwt_vc_presentation(req, res).catch(next);
        break;
      case "multi":
        create_jwt_vc_presentation_multi(req, res).catch(next);
        break;
      case "sdjwt":
        create_sd_jwt_presentation(req, res).catch(next);
        break;
      case "mdoc":
        create_mdoc_presentation(req, res).catch(next);
        break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Presentation page
  app.get("/stream/present/:id", (req, res) => {
    handleEvents("presentation", req, res);
  });

  // DC-API Presentation routes
  app.get("/present-dcapi/select/:id", (req, res) => {
    res.render(`present-dcapi/${req.query["credential-type"]}`, {"page": "present-dcapi", "presentationId": req.params.id});
  });

  app.get("/present-dcapi", (req, res) => {
    res.render("present-dcapi", {"page": "present-dcapi", "presentationId": uuidv4(), "demoAppUrl": DEMO_APP_NGROK_URL || ""});
  });

  app.get("/present-dcapi/init/:id", (req, res, next) => {
    switch(req.query["credential-type"]) {
      case "jwt":
        init_jwt_dcapi_presentation(req, res).catch(next);
        break;
      case "sdjwt":
        init_sdjwt_dcapi_presentation(req, res).catch(next);
        break;
      case "mdoc":
        init_mdoc_dcapi_presentation(req, res).catch(next);
        break;
      default:
        res.status(400).send("");
    }
  });

  // Browser forwards the DigitalCredential.data response here for verification
  app.post("/present-dcapi/response/:presentationId", (req, res, next) => {
    forward_dcapi_response(req, res).catch(next);
  });

  // ##      ## ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##   ##
  // ##  ##  ## ######   ########  ######### ##     ## ##     ## #####     ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##         ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  //  ###  ###  ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ACA-Py sends webhook events when something happens within ACA-Py (such as
    // when a credential is issued or a presentation has been varified). These
  // webhooks showcase the current state of ACA-Py flows and can be acted upon to
  // give users up-to-date and realtime info.

    app.post("/webhook/*", (req, res, next) => {
      logger.info("Webhook received: %s body_keys=%s", req.path, Object.keys(req.body).join(","));
      if (req.path == "/webhook/topic/oid4vci/") {
        // If there's no exchange ID, we can't look up the request
        if (!req.body.exchange_id) return;

        // Check to see if this belongs to us
        let exchange = exchangeCache.get(req.body.exchange_id);
        if (!exchange) return;

        // Dispatch event
        events.emit(`issuance-${exchange.registrationId}`, {type: "webhook", path: req.path, data: req.body});
      }
      if (req.path == "/webhook/topic/oid4vp/") {
        const lookupId = req.body.pres_def_id || req.body.dcql_query_id;
        logger.info("OID4VP webhook: state=%s pres_def_id=%s dcql_query_id=%s lookupId=%s",
          req.body.state, req.body.pres_def_id, req.body.dcql_query_id, lookupId);
        if (!lookupId) {
          logger.warn("OID4VP webhook: no lookupId, dropping");
          return;
        }

        // Check to see if this belongs to us
        let exchange = presentationCache.get(lookupId);
        logger.info("OID4VP webhook: cache lookup for %s → %s", lookupId, exchange ? `found (presentationId=${exchange.presentationId})` : "NOT FOUND");
        if (!exchange) return;

        // Dispatch event
        events.emit(`presentation-${exchange.presentationId}`, {type: "webhook", path: req.path, data: req.body});
      }
    });

  app.listen(3000, () => {
    console.log("App listening on port 3000");
  });
