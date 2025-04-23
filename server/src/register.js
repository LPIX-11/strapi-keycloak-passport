import middlewares from "./middlewares";

const register = ({ strapi }) => {
  strapi.log.info('🔄 Registering Strapi Keycloak Passport Plugin...');
  strapi.server.use(middlewares.jwtCookie);
};

export default register;
