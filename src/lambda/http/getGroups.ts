// import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
// import 'source-map-support/register'
// import { getAllGroups } from '../../businessLogic/groups';

// export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
//   console.log('Processing event: ', event)

//   const groups = await getAllGroups()

//   return {
//     statusCode: 200,
//     headers: {
//       'Access-Control-Allow-Origin': '*'
//     },
//     body: JSON.stringify({
//       items: groups
//     })
//   }
// }

import 'source-map-support/register'
import { getAllGroups } from '../../businessLogic/groups';

import * as express from 'express'
import * as awsServerlessExpress from 'aws-serverless-express'

const app = express()

app.get('/groups', async (_req, res) => {
  const groups = await getAllGroups()

  res.json({
    items: groups
  })
})

const server = awsServerlessExpress.createServer(app)
exports.handler = (event, context) => { awsServerlessExpress.proxy(server, event, context) }
