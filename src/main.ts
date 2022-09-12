import * as core from '@actions/core';
import * as github from '@actions/github';

import FormData from 'form-data';
import * as fs from 'fs';
import { https } from 'follow-redirects';
import jwt from 'jsonwebtoken';
import * as path from 'path';
import type { Readable } from 'stream';
import { pipeline } from 'stream/promises';

type UploadDetail = {
  uuid: string;
  channel: string;
  processed: boolean;
  submitted: boolean;
  url: string;
  valid: boolean;
  validation?: Record<string, unknown>;
  version: string;
};

type VersionDetail = {
  id: number;
  channel: 'listed' | 'unlisted';
  compatibility: Record<string, { min?: string; max?: string }>;
  edit_url: string;
  file: {
    id: number;
    created: string;
    hash: string;
    is_mozilla_signed_extension: boolean;
    optional_permissions: Array<string>;
    permissions: Array<string>;
    size: number;
    status: number;
    url: string;
  };
  license: {
    is_custom: boolean;
    name: Record<string, string> | null;
    text: Record<string, string> | null;
    url: string | null;
    slug: string | null;
  };
  release_notes: Record<string, string> | null;
  reviewed?: string;
  is_strict_compatibility_enabled: boolean;
  source: string | null;
  version: string;
};

async function main() {
  const octokit = github.getOctokit(process.env.GITHUB_TOKEN!);
  const {
    repo: { owner, repo },
  } = github.context;

  const releaseId = parseInt(core.getInput('release_id'), 10);
  console.log(`Fetching metadata for release ${releaseId}`);
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
  console.log(`Found add-on asset: ${addonAsset.name}`);

  // Fetch the asset
  const assetPath = path.join(process.env.GITHUB_WORKSPACE!, 'addon.zip');
  console.log(`Downloading ${addonAsset.browser_download_url} to ${assetPath}`);
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
  const {
    uuid,
    version,
    valid: initiallyValid,
  } = JSON.parse(uploadResponse) as UploadDetail;
  console.log(
    `Successfully uploaded add-on for version ${version} with uuid ${uuid}`
  );

  // Query the upload details API until it is valid
  //
  // Set an overall timeout of 10 minutes first, however.
  setTimeout(() => {
    core.setFailed('Timed out waiting for upload to be valid');
    process.exit(1);
  }, 10 * 60 * 1000);

  let valid = initiallyValid;
  while (!valid) {
    // Recommended polling interval is 5~10 seconds according to:
    // https://blog.mozilla.org/addons/2022/03/17/new-api-for-submitting-and-updating-add-ons/
    console.log('Waiting before checking if upload is valid');
    await new Promise((resolve) => setTimeout(resolve, 5000));

    console.log('Checking upload status...');
    const { valid, validation } = JSON.parse(
      await getFromAmo(`/api/v5/addons/upload/${uuid}`)
    ) as UploadDetail;
    if (valid) {
      console.log('Upload is valid');
    } else if (valid === false && validation) {
      // I have no idea what these validation objects look like.
      // The docs just say, "the validation results JSON blob".
      throw new Error(`Validation error: ${JSON.stringify(validation)}`);
    }
    console.log('Upload is still not valid');
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
  const { id: versionId, version: versionString } = JSON.parse(
    await postToAmo({
      path: `/api/v5/addons/addon/${addonId}/versions/`,
      jsonData: postData,
    })
  ) as VersionDetail;
  console.log(
    `Successfully created version ${versionString} (id: ${versionId})`
  );

  // Get the source asset (if any)
  const srcAssetName = core.getInput('src_asset_name');
  if (srcAssetName) {
    const srcAsset = release.data.assets.find((a) => a.name === srcAssetName);
    if (!srcAsset) {
      throw new Error(`No asset found with name ${srcAssetName}`);
    }
    console.log(`Found source asset: ${srcAsset.name}`);

    // Download the source asset
    const srcAssetPath = path.join(
      process.env.GITHUB_WORKSPACE!,
      'addon-src.zip'
    );
    console.log(
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
    console.log('Successfully uploaded source asset');
  }

  console.log('Publishing complete.');
}

main().catch((error) => {
  core.setFailed(error.message);
});

function getHttpsStream(url: string): Promise<Readable> {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Got status ${res.statusCode} for ${url}`));
        } else {
          resolve(res);
        }
      })
      .on('error', (err) => {
        reject(err);
      });
  });
}

const AMO_HOST = 'addons.mozilla.org';

function getFromAmo(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const url = `https://${AMO_HOST}${path}`;
    https
      .get(url, { auth: `JWT ${getJwtToken()}` }, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Got status ${res.statusCode} for ${url}`));
        } else {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve(body);
          });
        }
      })
      .on('error', (err) => {
        reject(err);
      });
  });
}

async function postToAmo({
  path,
  jsonData,
}: {
  path: string;
  jsonData: string;
}): Promise<string> {
  const options = {
    hostname: AMO_HOST,
    path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': jsonData.length,
    },
    auth: `JWT ${getJwtToken()}`,
  };
  const url = `https://${options.hostname}${options.path}`;

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`Got status ${res.statusCode} for ${url}`));
      }

      let response = '';
      res.on('data', (chunk) => {
        response += chunk;
      });
      res.on('end', () => {
        resolve(response);
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    req.write(jsonData);
    req.end();
  });
}

function uploadToAmo({
  path,
  formData,
  method = 'POST',
}: {
  path: string;
  formData: FormData;
  method?: string;
}): Promise<string> {
  return new Promise((resolve, reject) => {
    formData.submit(
      {
        host: AMO_HOST,
        method,
        path,
        protocol: 'https:',
        auth: `JWT ${getJwtToken()}`,
      },
      (err, res) => {
        if (err) {
          reject(err);
          return;
        }

        if (res.statusCode !== 200) {
          reject(
            new Error(
              `Got status ${res.statusCode} for https://${AMO_HOST}${path}`
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
