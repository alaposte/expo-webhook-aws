const crypto = require('crypto');
const safeCompare = require('safe-compare');

/**
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html
 * @param {Object} context
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 *
 */
exports.lambdaHandler = (event, context) => {
  const { body, headers } = event;
  const expoSignature = headers['expo-signature'];

  try {
    const hmac = crypto
      .createHmac('sha1', process.env.EXPO_WEBHOOK_SECRET)
      .update(body);
    const hash = `sha1=${hmac.digest('hex')}`;
    if (!safeCompare(expoSignature, hash)) {
      return createErrorResponse("Signatures didn't match!");
    } else {
      // download the artifact and copy it to the S3 bucket
      const parsedJson = JSON.parse(body);
      const { artifactUrl } = parsedJson;
      return createSuccessResponse(artifactUrl);
    }
  } catch (e) {
    return createErrorResponse(e.message);
  }
};

const createErrorResponse = (message, code = 404) => ({
  statusCode: code,
  body: JSON.stringify({
    message,
    errors: message ? [message] : null
  })
});

const createSuccessResponse = (message) => ({
  statusCode: 200,
  body: JSON.stringify({
    message: message,
    errors: null
  })
});
