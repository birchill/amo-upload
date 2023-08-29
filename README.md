# amo-upload

GitHub Action to upload a new Web Extension package to addons.mozilla.org.

Note that this action currently expects to be run based on a _release_ event.

## Usage

See [action.yml](action.yml)

<!-- start usage -->

```yaml
name: Publish
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    name: Publish to AMO

    steps:
      # ....

      - name: Publish
        uses: birchill/amo-upload@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          addon_id: <addon ID>
          amo_jwt_iss: ${{ secrets.AMO_JWT_ISS }}
          amo_jwt_secret: ${{ secrets.AMO_JWT_SECRET }}
          release_id: ${{ github.event.release.id }}
          addon_asset_name: <name packaged asset in release>
          src_asset_name: <name of source asset in release>
          release_notes: <release notes>
```

<!-- end usage -->

## Inputs

- `amo_jwt_iss` (required) - The JWT issuer (also referred to as the API key)
  from https://addons.mozilla.org/en-US/developers/addon/api/key/

- `amo_jwt_secret` (required) - The JWT secret from
  https://addons.mozilla.org/en-US/developers/addon/api/key/

- `addon_id` (required) - The numeric add-on ID, addon slug, or add-on GUID

- `release_id` (required) - The ID of the release to publish

- `release_notes` - The release notes to use for the new version. If not set,
  the body of the release will be used.

- `addon_asset_name` (required) - The last part of the name of the add-on asset
  within the release

- `src_asset_name` - The last part of the name of the source asset within the
  release
