module.exports = async (ctx, next) => {
  await next();

  if (
    (ctx.request.url === '/admin/login' || ctx.request.url === '/admin/renew-token') &&
    ctx.method === 'POST' &&
    ctx.status === 200 &&
    ctx.body?.data?.token
  ) {
    const token = ctx.body.data.token;

    ctx.cookies.set('jwtToken', token);
  }
};