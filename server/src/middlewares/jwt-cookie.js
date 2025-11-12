module.exports = async (ctx, next) => {
  if (
    (ctx.request.url === '/admin/login' || ctx.request.url === '/admin/renew-token') &&
    ctx.method === 'POST' &&
    ctx.status === 200 &&
    ctx.body?.data?.token
  ) {
    const token = ctx.body.data.token;

    ctx.cookies.set('jwtToken', token, {
      httpOnly: true,
      // ...process.env.NODE_ENV?.includes('prod') && {
      //   secure: true,
      //   rolling: true,
      //   sameSite: "none",
      // }
    });
  }

  await next();
};