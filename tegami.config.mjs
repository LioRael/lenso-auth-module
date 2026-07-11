/** Auth Cargo and npm packages remain independently versioned. */
export default {
  ignore: ["@lenso/auth-module-workspace"],
  npm: {
    // Publication order follows manifest dependencies without forcing unrelated bumps.
    bumpDep: () => false,
  },
  packages: {
    "lenso-module-auth": {},
    "lenso-module-auth-anonymous": {},
    "lenso-module-auth-device": {},
    "lenso-module-auth-github": {},
    "lenso-module-auth-google": {},
    "lenso-module-auth-oauth": {},
    "lenso-module-auth-oidc": {},
    "lenso-module-auth-password": {},
    "lenso-module-auth-phone": {},
    "@lenso/auth-console": {},
    "@lenso/auth-device-console": {},
    "@lenso/auth-provider-console": {},
  },
};
