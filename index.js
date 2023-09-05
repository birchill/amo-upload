// @ts-check
import * as core from '@actions/core';
import * as github from '@actions/github';

import FormData from 'form-data';
import jwt from 'jsonwebtoken';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';
import utf8 from 'utf8';

/**
 * @typedef {object} UploadDetail
 * @property {string} uuid
 * @property {string} channel
 * @property {boolean} processed
 * @property {boolean} submitted
 * @property {string} url
 * @property {boolean} valid
 * @property {Record<string, unknown>} [validation]
 * @property {string} version
 */

/**
 * @typedef {object} VersionDetail
 * @property {number} id
 * @property {'listed' | 'unlisted'} channel
 * @property {Record<string, { min?: string; max?: string }>} compatibility
 * @property {string} edit_url
 * @property {FileDetail} file
 * @property {LicenseDetail} license
 * @property {Record<string, string> | null} release_notes
 * @property {string} [reviewed]
 * @property {boolean} is_strict_compatibility_enabled
 * @property {string | null} source
 * @property {string} version
 */

/**
 * @typedef {object} FileDetail
 * @property {number} id
 * @property {string} created
 * @property {string} hash
 * @property {boolean} is_mozilla_signed_extension
 * @property {Array<string>} optional_permissions
 * @property {Array<string>} permissions
 * @property {number} size
 * @property {number} status
 * @property {string} url
 */

/**
 * @typedef {object} LicenseDetail
 * @property {boolean} is_custom
 * @property {Record<string, string> | null} name
 * @property {Record<string, string> | null} text
 * @property {string | null} url
 * @property {string | null} slug
 */

async function main() {
  const octokit = github.getOctokit(
    /** @type string */ (process.env.GITHUB_TOKEN)
  );
  const {
    repo: { owner, repo },
  } = github.context;

  const releaseId = parseInt(core.getInput('release_id'), 10);
  core.info(`Fetching metadata for release ${releaseId}`);
  const release = await octokit.rest.repos.getRelease({
    owner,
    repo,
    release_id: releaseId,
  });

  // Look for the add-on asset in the release's assets
  const addonAssetName = core.getInput('addon_asset_name');
  const addonAsset = release.data.assets.find((a) => a.name === addonAssetName);
  if (!addonAsset) {
    throw new Error(`No asset found with name ${addonAssetName}`);
  }
  core.info(`Found add-on asset: ${addonAsset.name}`);

  // Fetch the asset
  const workspace = /** @type string */ (process.env.GITHUB_WORKSPACE);
  const assetPath = path.join(workspace, 'addon.zip');
  core.info(`Downloading ${addonAsset.browser_download_url} to ${assetPath}`);
  await pipeline(
    await getHttpsStream(addonAsset.browser_download_url),
    fs.createWriteStream(assetPath)
  );

  // Upload the asset
  const formData = new FormData();
  formData.append('upload', fs.createReadStream(assetPath));
  formData.append('channel', 'listed');
  const uploadResponse = await uploadToAmo({
    path: '/api/v5/addons/upload/',
    formData,
  });
  /** @type UploadDetail */
  const { uuid, version, valid: initiallyValid } = JSON.parse(uploadResponse);
  core.info(
    `Successfully uploaded add-on for version ${version} with uuid ${uuid}`
  );

  // Query the upload details API until it is valid
  //
  // Set an overall timeout of 10 minutes first, however.
  const tenMinuteTimeout = setTimeout(
    () => {
      core.setFailed('Timed out waiting for upload to be valid');
      process.exit(1);
    },
    10 * 60 * 1000
  );

  try {
    let valid = initiallyValid;
    while (!valid) {
      // Recommended polling interval is 5~10 seconds according to:
      // https://blog.mozilla.org/addons/2022/03/17/new-api-for-submitting-and-updating-add-ons/
      core.info('Waiting before checking if upload is valid');
      await new Promise((resolve) => setTimeout(resolve, 5000));

      core.info('Checking upload status...');
      /** @type UploadDetail */
      const { valid, validation } = JSON.parse(
        await getFromAmo(`/api/v5/addons/upload/${uuid}`)
      );
      if (valid) {
        core.info('Upload is valid');
        break;
      } else if (valid === false && validation) {
        // I have no idea what these validation objects look like.
        // The docs just say, "the validation results JSON blob".
        throw new Error(`Validation error: ${JSON.stringify(validation)}`);
      }
      core.info('Upload is still not valid');
    }
  } finally {
    clearTimeout(tenMinuteTimeout);
  }

  // Create a new version with the provided release notes
  const addonId = core.getInput('addon_id');
  // TODO: Support a release_notes_json parameter that allows specifying a JSON
  // string with all the localized release notes.
  const releaseNotes = core.getInput('release_notes') || release.data.body;
  const postData = JSON.stringify({
    compatibility: ['android', 'firefox'],
    release_notes: { 'en-US': releaseNotes },
    upload: uuid,
  });
  /** @type VersionDetail */
  const { id: versionId, version: versionString } = JSON.parse(
    await postToAmo({
      path: `/api/v5/addons/addon/${addonId}/versions/`,
      jsonData: postData,
    })
  );
  core.info(`Successfully created version ${versionString} (id: ${versionId})`);

  // Get the source asset (if any)
  const srcAssetName = core.getInput('src_asset_name');
  if (srcAssetName) {
    const srcAsset = release.data.assets.find((a) => a.name === srcAssetName);
    if (!srcAsset) {
      throw new Error(`No asset found with name ${srcAssetName}`);
    }
    core.info(`Found source asset: ${srcAsset.name}`);

    // Download the source asset
    const srcAssetPath = path.join(workspace, 'addon-src.zip');
    core.info(
      `Downloading ${srcAsset.browser_download_url} to ${srcAssetPath}`
    );
    await pipeline(
      await getHttpsStream(srcAsset.browser_download_url),
      fs.createWriteStream(srcAssetPath)
    );

    // Upload the source asset
    const form = new FormData();
    form.append('source', fs.createReadStream(srcAssetPath));
    uploadToAmo({
      path: `/api/v5/addons/addon/${addonId}/versions/${versionId}/`,
      formData: form,
      method: 'PATCH',
    });
    core.info('Successfully uploaded source asset');
  }

  core.info('Publishing complete.');
}

main().catch((error) => {
  core.setFailed(error.message);
});

/**
 * @param {string} url
 * @returns {Promise<Readable>}
 */
async function getHttpsStream(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(
      `Got status ${res.status} (${res.statusText}) for GET ${url}`
    );
  }

  if (!res.body) {
    throw new Error('Response has no body');
  }

  // See:
  //
  // https://stackoverflow.com/questions/63630114/argument-of-type-readablestreamany-is-not-assignable-to-parameter-of-type-r
  // https://stackoverflow.com/questions/73308289/typescript-error-converting-a-native-fetch-body-webstream-to-a-node-stream
  // for why the cast is necessary
  return Readable.fromWeb(
    /** @type import('stream/web').ReadableStream<any> */ (res.body)
  );
}

const AMO_HOST = 'addons.mozilla.org';

/**
 * @param {string} path
 * @returns {Promise<string>}
 */
async function getFromAmo(path) {
  const url = `https://${AMO_HOST}${path}`;
  const res = await fetch(url, {
    headers: { Authorization: `JWT ${getJwtToken()}` },
  });

  if (!res.ok) {
    throw new Error(
      `Got status ${res.status} (${res.statusText}) for GET ${url}`
    );
  }

  return res.text();
}

/**
 * @param {object} options
 * @param {string} options.path
 * @param {string} options.jsonData
 * @returns {Promise<string>}
 */
async function postToAmo({ path, jsonData }) {
  const url = `https://${AMO_HOST}${path}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `JWT ${getJwtToken()}`,
      'Content-Type': 'application/json',
      'Content-Length': String(utf8.encode(jsonData).length),
    },
    body: jsonData,
  });

  return res.text();
}

/**
 * @param {object} options
 * @param {string} options.path
 * @param {FormData} options.formData
 * @param {string} [options.method]
 * @returns {Promise<string>}
 */
function uploadToAmo({ path, formData, method = 'POST' }) {
  return new Promise((resolve, reject) => {
    formData.submit(
      {
        host: AMO_HOST,
        method,
        path,
        protocol: 'https:',
        headers: {
          Authorization: `JWT ${getJwtToken()}`,
        },
      },
      (err, res) => {
        if (err) {
          reject(err);
          return;
        }

        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          reject(
            new Error(
              `Got status ${res.statusCode} for POST https://${AMO_HOST}${path}`
            )
          );
        } else {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve(body);
          });
        }
      }
    );
  });
}

function getJwtToken() {
  const jwtIss = core.getInput('amo_jwt_iss');
  const jwtSecret = core.getInput('amo_jwt_secret');
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = {
    iss: jwtIss,
    jti: Math.random().toString(),
    iat: issuedAt,
    exp: issuedAt + 60,
  };
  return jwt.sign(payload, jwtSecret, {
    algorithm: 'HS256', // HMAC-SHA256 signing algorithm
  });
}
