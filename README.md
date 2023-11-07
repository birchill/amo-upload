# amo-upload

GitHub Action to upload a new Web Extension package to addons.mozilla.org.

## Usage

See [action.yml](action.yml)

<!-- start usage -->

```yaml
- uses: birchill/amo-upload@v1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    addon_id: <addon ID>
    amo_jwt_iss: ${{ secrets.AMO_JWT_ISS }}
    amo_jwt_secret: ${{ secrets.AMO_JWT_SECRET }}
    addon_file: addon.zip
    src_asset_name: src.zip
    release_notes: <release notes>
```

<!-- end usage -->

## Inputs

- `amo_jwt_iss` (required) - The JWT issuer (also referred to as the API key)
  from https://addons.mozilla.org/en-US/developers/addon/api/key/

- `amo_jwt_secret` (required) - The JWT secret from
  https://addons.mozilla.org/en-US/developers/addon/api/key/

- `addon_id` (required) - The numeric add-on ID, addon slug, or add-on GUID

- `addon_file` (required) - The filename of the addon asset relative to
  `$GITHUB_WORKSPACE`.

- `src_file` - The filename of an optional source archive relative to
  `$GITHUB_WORKSPACE`.

- `release_notes` - The release notes to use for the new version.

  Note that currently any supplied release notes are set for the `en-US` locale
  only.
