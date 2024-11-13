import os

class Config:
    """Base configuration class."""
    # Secret Key for Flask app
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_default_secret_key')

    # AWS Configuration
    AWS_REGION = 'us-east-1'  # Region for AWS services
    AWS_PROFILE = os.environ.get('AWS_PROFILE', 'myProfile')  # AWS Profile name

    # DynamoDB Table Names
    EVENT_TABLE_NAMES = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']
    
    # S3 Configuration
    BUCKET_NAME = 'a3pictures'
    TEXT_FILE_KEY = 'AustralianFoodandWineShow.txt'
    
    # SES Configuration
    SENDER_EMAIL = "andrewjoyce2022@outlook.com"

    # Lambda Function Names
    LAMBDA_FUNCTION_NAME = 'InstagramWebhookFunction'
    UPDATE_EVENT_CAPACITY_FUNCTION_NAME = 'UpdateEventCapacityFunction'

    # CloudFront Domain for images
    CLOUDFRONT_DOMAIN = 'd1ucmletbndp5t.cloudfront.net'
    
    # Logging Configuration
    LOGGING_LEVEL = os.environ.get('LOGGING_LEVEL', 'INFO').upper()
