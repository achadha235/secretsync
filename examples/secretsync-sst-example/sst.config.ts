/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "secretsync-sst-example",
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: ["production"].includes(input?.stage),
      home: "aws",
      providers: {
        aws: {
          region: process.env.AWS_REGION,
        },
      },
    };
  },
  async run() {
    const secretOne = new sst.Secret("SecretOne", "secret-one-placeholder");
    const secretTwo = new sst.Secret("SecretTwo", "secret-two-placeholder");

    const testFunction = new sst.aws.Function("TestFunction", {
      handler: "src/lambda.handler",
      link: [secretOne, secretTwo],
      url: true,
    });

    return {
      testFunctionUrl: testFunction.url,
    };
  },
});
