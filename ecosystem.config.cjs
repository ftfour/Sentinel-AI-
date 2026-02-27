module.exports = {
  apps: [
    {
      name: 'sentinel-ai-ru',
      script: 'npm',
      args: 'run start',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        NODE_OPTIONS: '--dns-result-order=ipv4first',
      },
    },
  ],
};
