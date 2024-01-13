import boto3
import time
import os
import json
import logging

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global AWS clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
cf_client = boto3.client('cloudfront')
acm_client = boto3.client('acm')

def lambda_handler(event, context):
    try:
        for record in event['Records']:
            body = json.loads(record['Sns']['Message'])
            action = body['action']

            # Define functions for each action
            actions = {
                's3_create': s3_create_function,
                's3_delete_public_access_block': s3_delete_public_access_block_function,
                's3_allow_public_access': s3_allow_public_access_function,
                's3_update_cors': s3_update_cors_function,
                's3_update_website': s3_update_website_function,
                's3_delete': s3_delete_function,
                'cf_create': cf_create_function,
                'cf_check_deployed': cf_check_deployed_function,
                'cf_disable': cf_disable_function,
                'cf_delete': cf_delete_function,
                'cf_invalidate': cf_invalidate_function,
                'acm_delete': acm_delete_function,
            }

            result = actions.get(action, default_action)(body)
            logger.info(f"Action {action} executed with result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': 'Error processing the request'
        }

def publish_to_sns(topic_arn, subject, message):
    try:
        sns_client.publish(TargetArn=topic_arn, Subject=subject, Message=json.dumps(message))
    except Exception as e:
        logger.error(f"Error publishing to SNS: {str(e)}")

def s3_create_function(body):
    try:
        # Logic for s3_create action
        if 'region_name' in body:
            if body['region_name'] == 'us-east-1':
                s3_client = boto3.client('s3', region_name=body['region_name'])
                s3_client.create_bucket(Bucket=body['bucket_name'])
            else:
                s3_client = boto3.client('s3', region_name=body['region_name'])
                location = {'LocationConstraint': body['region_name']}
                s3_client.create_bucket(Bucket=body['bucket_name'], CreateBucketConfiguration=location)
        else:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=body['bucket_name'])

        # update database with bucket name
        param = {'model':'KyteSite','field':'id','value':body['site_id'],'data':{}}
        if body['is_website']:
            param['data']['s3BucketName'] = body['bucket_name']
        else:
            param['data']['s3MediaBucketName'] = body['bucket_name']
        db_request = {'action':'update', 'db_name':os.environ['db_name'], 'param':param, 'callerId':str(time.time())}
        publish_to_sns(os.environ['db_transaction_topic'], str(body['site_id']), db_request)

        # next queue up for deleting public access block
        body['action'] = 's3_delete_public_access_block'
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' created'
        }
    except Exception as e:
        logger.error(f"Error in s3_create_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error creating S3 bucket'}
    
def s3_delete_public_access_block_function(body):
    try:
        s3 = boto3.client('s3')
        # delete public access block of new bucket
        s3.delete_public_access_block(Bucket=body['bucket_name'])

        # next queue up for allowing public access
        body['action'] = 's3_allow_public_access'
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' deleted public access block'
        }
    except Exception as e:
        logger.error(f"Error in s3_delete_public_access_block_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error deleting S3 public access block'}

def s3_allow_public_access_function(body):
    try:
        s3 = boto3.client('s3')
        # enable public access of bucket
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::"+body['bucket_name']+"/*"
            }]
        }
        policy_json = json.dumps(bucket_policy)
        s3.put_bucket_policy(Bucket=body['bucket_name'], Policy=policy_json)
        
        # if body['is_media'] is true, then add message to sns for updating CORS policy
        if body['is_media']:
            body['action'] = 's3_update_cors'
            publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        # if body['is_website'] is true, then add message to sns for updating website configuration
        elif body['is_website']:
            body['action'] = 's3_update_website'
            publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        
        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' enabled public access'
        }
    except Exception as e:
        logger.error(f"Error in s3_allow_public_access_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error applying S3 public access policy'}

def s3_update_cors_function(body):
    try:
        s3 = boto3.client('s3')
        # update CORS policy of bucket
        cors_configuration = {
            'CORSRules': [
                {
                    'AllowedHeaders': ['*'],
                    'AllowedMethods': ['GET', 'POST'],
                    'AllowedOrigins': ['*'],
                }
            ]
        }
        # put bucket CORS configuration
        s3.put_bucket_cors(Bucket=body['bucket_name'], CORSConfiguration=cors_configuration)

        # next send sns message for create a cloudfront distribution for the bucket
        body['action'] = 'cf_create'
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)

        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' updated CORS'
        }
    except Exception as e:
        logger.error(f"Error in s3_update_cors_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error applying S3 CORS policy'}

def s3_update_website_function(body):
    try:
        s3 = boto3.client('s3')
        # update website configuration of bucket
        website_configuration = {
            'ErrorDocument': {
                'Key': 'error.html'
            },
            'IndexDocument': {
                'Suffix': 'index.html'
            }
        }
        # put bucket website configuration
        s3.put_bucket_website(Bucket=body['bucket_name'], WebsiteConfiguration=website_configuration)

        # next send sns message for create a cloudfront distribution for the bucket
        body['action'] = 'cf_create'
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)

        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' updated website'
        }
    except Exception as e:
        logger.error(f"Error in s3_update_website_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error applying S3 static website policies'}

def s3_delete_function(body):
    try:
        # Logic for s3_delete action
        s3 = boto3.resource('s3', region_name=body['region_name'] if 'region_name' in body else None)
        s3_bucket = s3.Bucket(body['bucket_name'])
        # check if versioning is enabled
        bucket_versioning = s3.BucketVersioning(body['bucket_name'])
        # Delete all objects in the bucket before deleting the bucket itself
        if bucket_versioning.status == 'Enabled':
            s3_bucket.object_versions.delete()
        else:
            s3_bucket.objects.all().delete()

        # Delete the bucket
        s3_bucket.delete()

        # if bucket was successfully deleted and cf_id is present, then move to next task
        if body['cf_id'] is not None:
            body['action'] = 'cf_disable'
            publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        return {
            'statusCode': 200,
            'body': 'Bucket '+body['bucket_name']+' deleted'
        }
    except Exception as e:
        logger.error(f"Error in s3_delete_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error deleting S3 bucket'}

def cf_create_function(body):
    try:
        cf = boto3.client('cloudfront')
        # create cloudfront distribution
        distribution = cf.create_distribution(
            DistributionConfig={
                'CallerReference': str(time.time()),
                'Comment': 'Created by Kyte on '+str(time.time())+' for bucket '+body['bucket_name'],
                'Enabled': True,
                'DefaultRootObject': 'index.html' if body['is_website'] else '',
                'Origins': {
                    'Quantity': 1,
                    'Items': [{
                        'Id': body['bucket_name'],
                        'DomainName': body['cf_origin'],
                        'OriginShield': {
                            'Enabled': True,
                            'OriginShieldRegion': body['region_name']
                        },
                        'CustomOriginConfig': {
                            'HTTPPort': 80,
                            'HTTPSPort': 443,
                            'OriginProtocolPolicy': 'http-only',
                        }
                    }]
                },
                'DefaultCacheBehavior': {
                    'TargetOriginId': body['bucket_name'],
                    'ForwardedValues': {
                        'QueryString': False,
                        'Cookies': {
                            'Forward': 'none'
                        },
                    },
                    'Compress': True,
                    'ViewerProtocolPolicy': 'redirect-to-https',
                    'DefaultTTL': 86400,
                    'MinTTL': 3600
                },
                'PriceClass': 'PriceClass_All'
            }
        )
        
        # update database with cloudfront id and domain name
        param = {
            'model':'KyteSite',
            'field':'id',
            'value':body['site_id'],
            'data':{}
        }
        # append to param['data'] the key-value 'status':'active' if is_website is true
        if body['is_website']:
            param['data']['status'] = 'active'
            param['data']['cfDistributionId'] = distribution['Distribution']['Id']
            param['data']['cfDomain'] = distribution['Distribution']['DomainName']
        else:
            param['data']['cfMediaDistributionId'] = distribution['Distribution']['Id']
            param['data']['cfMediaDomain'] = distribution['Distribution']['DomainName']

        body['action'] = 'cf_check_deployed'
        body['cf_id'] = distribution['Distribution']['Id']
        body['db_param'] = param
        body['retry'] = 0 # retry count
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)

        return {
            'statusCode': 200,
            'body': 'CloudFront distribution '+distribution['Distribution']['Id']+' created'
        }
    except Exception as e:
        logger.error(f"Error in cf_create_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error creating CloudFront distribution'}

def cf_check_deployed_function(body):
    try:
        # Logic for cf_delete action
        cf = boto3.client('cloudfront')

        # check the status of the distribution and delete
        distribution = cf.get_distribution(Id=body['cf_id'])
        distribution_config = distribution['Distribution']['DistributionConfig']
        if distribution_config['Enabled'] == True and distribution['Distribution']['Status']=='Deployed':
            db_request = {'action':'update', 'db_name':os.environ['db_name'], 'param':body['db_param'], 'callerId':str(time.time())}
            publish_to_sns(os.environ['db_transaction_topic'], str(body['site_id']), db_request)
        else:
            retry_limit = os.environ.get('retry_limit', 5)
            try:
                retry_limit = int(retry_limit)
            except ValueError:
                retry_limit = 5

            sleep_time = os.environ.get('sleep_time', 5)
            try:
                sleep_time = int(sleep_time)
            except ValueError:
                sleep_time = 5

            if body['retry'] >= retry_limit:
                logger.error(f"Reached maximum retry of {retry_limit}")
                return {'statusCode': 500, 'body': f"Reached maximum retry of {retry_limit}"}
            else:
                body['retry'] += 1 # increment retry count
                time.sleep(sleep_time)
                body['CallerReference'] = str(time.time()).replace(".", "")
                publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
                return {
                    'statusCode': 200,
                    'body': 'CloudFront distribution '+body['cf_id']+' not deployed yet, added back to queue'
                }
    except Exception as e:
        logger.error(f"Error in cf_check_deployed_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error checking deployment status for CloudFront distribution'+body['cf_id']}

def cf_disable_function(body):
    try:
        # Logic for cf_disable action
        cf = boto3.client('cloudfront')

        distribution = cf.get_distribution(Id=body['cf_id'])
        ETag = distribution['ETag']
        distribution_config = distribution['Distribution']['DistributionConfig']
        distribution_config['Enabled'] = False

        cf.update_distribution(DistributionConfig=distribution_config, Id=body['cf_id'], IfMatch=ETag)
        # update action to cf_delete and send message to sns
        body['action'] = 'cf_delete'
        body['retry'] = 0 # retry count
        publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
        
        return {
            'statusCode': 200,
            'body': 'CloudFront distribution '+body['cf_id']+' disabled'
        }
    except Exception as e:
        logger.error(f"Error in cf_disable_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error disabling CloudFront distribution'}

def cf_delete_function(body):
    try:
        # Logic for cf_delete action
        cf = boto3.client('cloudfront')

        # check the status of the distribution and delete
        distribution = cf.get_distribution(Id=body['cf_id'])
        ETag = distribution['ETag']
        distribution_config = distribution['Distribution']['DistributionConfig']
        if distribution_config['Enabled'] == False and distribution['Distribution']['Status']=='Deployed':
            cf.delete_distribution(Id=body['cf_id'], IfMatch=ETag)
            # update database to mark site as deleted
            param = {'model':'KyteSite','field':'id','value':body['site_id'],'data':{'status':'deleted','deleted':1}}
            db_request = {'action':'update', 'db_name':os.environ['db_name'], 'param':param, 'callerId':str(time.time())}
            publish_to_sns(os.environ['db_transaction_topic'], str(body['site_id']), db_request)
            
            # check if acm_arn is not null, if not null then update action to acm_delete and send message to sns
            if 'acm_arn' in body:
                body['action'] = 'acm_delete'
                publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
            return {
                'statusCode': 200,
                'body': 'CloudFront distribution '+body['cf_id']+' deleted'
            }
        else:
            retry_limit = os.environ.get('retry_limit', 5)
            try:
                retry_limit = int(retry_limit)
            except ValueError:
                retry_limit = 5

            sleep_time = os.environ.get('sleep_time', 5)
            try:
                sleep_time = int(sleep_time)
            except ValueError:
                sleep_time = 5
                
            if body['retry'] >= retry_limit:
                logger.error(f"Reached maximum retry of {retry_limit}")
                return {'statusCode': 500, 'body': f"Reached maximum retry of {retry_limit}"}
            else:
                body['retry'] += 1 # increment retry count
                # if disabled, if not disabled then send message to sns
                time.sleep(sleep_time)
                body['CallerReference'] = str(time.time()).replace(".", "")
                publish_to_sns(os.environ['site_management_topic'], str(body['site_id']), body)
                return {
                    'statusCode': 200,
                    'body': 'CloudFront distribution '+body['cf_id']+' not disabled yet, added back to queue'
                }
    except Exception as e:
        logger.error(f"Error in cf_delete_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error deleting CloudFront distribution'}

def cf_invalidate_function(body):
    try:
        # Logic for cf_invalidate action
        cf = boto3.client('cloudfront')
        # create a cloudfront invalidation
        cf_invalidation = cf.create_invalidation(
            DistributionId=body['cf_id'],
            InvalidationBatch={
                'Paths': {
                    'Quantity': len(body['cf_invalidation_paths']),
                    'Items': body['cf_invalidation_paths']
                },
                'CallerReference': str(time.time()).replace(".", "")
            }
        )
        return {
            'statusCode': 200,
            'body': 'Successfully invalidated distribution '+body['cf_id']
        }
    except Exception as e:
        logger.error(f"Error in cf_invalidate_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error invalidating CloudFront distribution'}

def acm_delete_function(body):
    try:
        acm = boto3.client('acm')
        acm.delete_certificate(CertificateArn=body['acm_arn'])
        return {
            'statusCode': 200,
            'body': 'ACM certificate '+body['acm_arn']+' deleted'
        }
    except Exception as e:
        logger.error(f"Error in acm_delete_function: {str(e)}")
        return {'statusCode': 500, 'body': 'Error deleting ACM certificate'}

def default_action(body):
    # Handle default action or invalid action
    logger.warning(f"Unknown action requested: {body.get('action')}")
    return {
        'statusCode': 400,
        'body': 'Unknown action requested: '+body['action']
    }