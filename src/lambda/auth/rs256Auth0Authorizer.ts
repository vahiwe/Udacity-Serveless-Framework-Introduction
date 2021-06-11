import { CustomAuthorizerEvent, CustomAuthorizerResult, CustomAuthorizerHandler, CustomAuthorizerCallback } from 'aws-lambda'
import 'source-map-support/register'
import * as middy from 'middy'
import { secretsManager } from 'middy/middlewares'
import * as AWS  from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
const XAWS = AWSXRay.captureAWS(AWS)

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `...`


export const handler = async (event: CustomAuthorizerEvent, context): Promise<CustomAuthorizerResult> => {
    try {
      const decodedToken = verifyToken(event.authorizationToken)
        console.log('User was authorized')
    
        return {
          principalId: decodedToken.sub,
          policyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: '*'
              }
            ]
          }
        }
      } catch (e) {
        console.log('User was not authorized', e.message)
    
        return {
          principalId: 'user',
          policyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: '*'
              }
            ]
          }
        }
      }

}

function verifyToken(authHeader: string): JwtToken {
    if (!authHeader)
      throw new Error('No authentication header')
  
    if (!authHeader.toLowerCase().startsWith('bearer '))
      throw new Error('Invalid authentication header')
  
    const split = authHeader.split(' ')
    const token = split[1]

    // const secretObject: any = await getSecret()
    // const secret = secretObject[secretField]

    // if (token !== "123")
    //   throw new Error('Invalid token')

    return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}