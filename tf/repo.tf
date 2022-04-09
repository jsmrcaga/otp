module repo {
  source = "git@github.com:jsmrcaga/terraform-modules//github-repo?ref=v0.0.2"

  name = "otp"
  description = "A simple NodeJS 2FA TOTP and HOTP generator"
  topics = ["totp", "2fa", "hotp", "node", "nodejs"]

  actions = {
    secrets = {
      NPM_TOKEN = var.npm_token
    }
  }
}
