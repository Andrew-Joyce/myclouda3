# Imports the libraries for logging, json handling, and file operations
import logging
import json
import os
import zipfile
import time
import markdown
from datetime import datetime

# Imports Flask modules for routing, rendering templates, handling requests, and session management
from flask import jsonify

# Imports AWS SDK (boto3) and external libraries for HTTP requests and Flask-related tasks
import boto3
import requests
from flask import Flask, Response, render_template, request, jsonify, redirect, session, url_for, flash, g
from functools import wraps
from botocore.exceptions import ClientError, NoCredentialsError

# Initialises SES for sending email through AWS SES (Simple Email Service)
ses_client = boto3.client('ses', region_name='us-east-1')

# Initialises the Flask application instance
app = Flask(__name__)
# The Secret key for securely signing the session cookie
app.secret_key = 'your_secret_key'

# CloudFront domain URL for serving static content 
cloudfront_domain = 'd1ucmletbndp5t.cloudfront.net'

# Setts up logging to track events in the application
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)  # Logger initialization is only needed once
logger.setLevel(logging.DEBUG)  # Set the log level to DEBUG to capture all levels of log messages


#This function runs before every request is handled by Flask.
# It logs the session data and requests the headers to track what is happening
# The connections to different AWS services (like S3, DynamoDB, SES, and API Gateway) are established. 
@app.before_request
def before_request():
    logger.debug(f"Session data at request start: {session}")
    logger.debug(f"Request headers: {request.headers}")
    boto_session = boto3.Session()
    g.s3 = boto_session.client('s3', region_name='us-east-1')
    g.dynamodb = boto_session.resource('dynamodb', region_name='us-east-1')
    g.ses_client = boto_session.client('ses', region_name='us-east-1')
    g.api_gateway_client = boto_session.client('apigateway', region_name='us-east-1')

#This function runs before every request is handled by Flask.
# It logs the session data and requests the headers to track what is happening
# The connections to different AWS services (like S3, DynamoDB, SES, and API Gateway) are established. 
@app.before_request
def before_request():
    logger.debug(f"Session data at request start: {session}")
    logger.debug(f"Request headers: {request.headers}")
    boto_session = boto3.Session()
    g.s3 = boto_session.client('s3', region_name='us-east-1')
    g.dynamodb = boto_session.resource('dynamodb', region_name='us-east-1')
    g.ses_client = boto_session.client('ses', region_name='us-east-1')
    g.api_gateway_client = boto_session.client('apigateway', region_name='us-east-1')

# Lists the event table names in the database
event_table_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']

# Names of the S3 bucket where the static files are stored
bucket_name = 'a3pictures'

# Sets the key for accessing the specific text file in the S3 bucket
text_file_key = 'AustralianFoodandWineShow.txt'

# Establishes the sender email address used for sending email notifications
sender_email = "andrewjoyce2022@outlook.com"

# Names of the AWS Lambda function that updates event capacity
update_event_capacity_function_name = 'UpdateEventCapacityFunction'


# Creates and returns a Lambda client using boto3 to interact with AWS Lambda.
def get_lambda_client():
    return boto3.client('lambda', region_name='us-east-1')

boto_session = boto3.Session()
logger.info(f"Using AWS profile: {boto_session.profile_name}")

# Manages the admin login process. The route is triggered when an admin tries to log in using their credentials.
# The login credentials (username and password)are processed via the POST request.
# The credentials are validated using the `check_auth` function.
# Confirms whether the login was successful or failed.
@app.route('/admin/login', methods=['POST'])
def admin_login():
    auth = request.authorization
    logger.debug(f"Received login attempt. Username: {auth.username if auth else 'No username'}")
    if auth and check_auth(auth.username, auth.password):
        # Successful login
        logger.debug(f"Login successful for user: {auth.username}")
        return jsonify({"message": "Login successful"}), 200
    else:
        # Failed login
        logger.warning(f"Invalid login attempt for username: {auth.username if auth else 'No username'}")
        return jsonify({"message": "Invalid credentials"}), 401

# Manages the GET requests to the admin page.
# The admin page is rendered with the event descriptions, either with a login form or event data.
@app.route('/admin', methods=['GET'])
def admin_get():
    logger.debug("Handling GET request for admin page.")
    events = get_event_descriptions()
    if 'user' not in session:
        logger.debug("No user in session, showing login form.")
        return render_template('admin.html', events=events)
    logger.debug(f"Rendering the admin template with {len(events)} events.")
    return render_template('admin.html', events=events)


# Manages the POST requests to the admin page for login.
# The program verifies if the user is already logged in.
# The user will be logged in if the creditentials are correct
# An error message will be displayed if they are incorrect
# On validating the creditentials the admin.html will be rendered. 
@app.route('/admin', methods=['POST'])
def admin_post():
    logger.debug("Handling POST request for admin page.")
    if 'user' not in session:
        auth = request.authorization
        if auth and check_auth(auth.username, auth.password):
            session['user'] = auth.username
            logger.debug(f"Authentication successful. User session set: {session}")
            return redirect(url_for('admin_get'))  
        else:
            flash("Invalid credentials. Please try again.", "error")
            logger.warning(f"Invalid credentials for user: {auth.username if auth else 'Unknown'}")
            return render_template('admin.html')
    logger.debug("User already authenticated. Redirecting to admin page.")
    return redirect(url_for('admin_get'))  


# Manages GET requests to the admin page.
# Logs the start of handling the GET request for the admin page.
# Validates if the user is logged in by looking for 'user' in the session.
# Verifies no user is in the session and shows the login form by rendering the admin page.
def handle_get_request():
    logger.debug("Handling GET request for admin page.")
    if 'user' not in session:
        logger.debug("No user in session, showing login form.")
        return render_template('admin.html')
    logger.debug("Fetching and sanitizing events...")
    sanitized_events = fetch_and_sanitize_events()
    logger.debug(f"Rendering the admin template with {len(sanitized_events)} events.")
    return render_template('admin.html', events=sanitized_events)

# Manages POST requests for admin page login.
# Validates if the user is logged in and tries to authenticate them if they are not.
# If authenicated, sets the user session and redirects to the admin page.
# If not authenticated, shows an error message and re-renders the admin page.
# For users already logged in, the program redirects directly to the admin page.
def handle_post_request():
    logger.debug("Handling POST request for admin page.")
    if 'user' not in session:
        auth = request.authorization
        if auth and check_auth(auth.username, auth.password):
            session['user'] = auth.username
            logger.debug(f"Authentication successful. User session set: {session}")
            return redirect(url_for('admin'))
        else:
            flash("Invalid credentials. Please try again.", "error")
            logger.warning(f"Invalid credentials for user: {auth.username if auth else 'Unknown'}")
            return render_template('admin.html')
    logger.debug("User already authenticated. Redirecting to admin page.")
    return redirect(url_for('admin'))


# Manages the calls of the event descriptions and sanitises them by validating the data.
# Logs the process of fetching and sanitizing events. 
# Validates if the event data is in the correct format.
# Returns a list of sanitized events, logging details about each event name.
def fetch_and_sanitize_events():
    logger.debug("Fetching event descriptions...")
    try:
        events = get_event_descriptions()  
        logger.debug(f"Fetched events: {events}")
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        events = []
    if not events or not isinstance(events, list):
        logger.error("Event data is invalid or empty, falling back to an empty list.")
        events = []  
    else:
        logger.debug("Event data is in valid list format.")
    sanitized_events = []
    for event in events:
        if isinstance(event, dict) and all(key in event for key in ['event_name', 'event_date', 'remaining_capacity', 'event_location', 'event_address', 'event_description']):
            sanitized_events.append(event)
        else:
            logger.warning(f"Skipping invalid event data: {event}")
    logger.debug(f"Sanitized Events data: {sanitized_events}")
    if sanitized_events:
        for event in sanitized_events:
            logger.debug(f"Event name: {event.get('event_name', 'No event name found')}")  # Log each event name
    else:
        logger.warning("No sanitized events found.")
    return sanitized_events

# Zips the Lambda function code into a zip file for deployment.
# Creates a zip file called 'lambda_function.zip' and adds the 'event_capacity_lambda.py' file to it.
def zip_lambda_function_code():
    try:
        lambda_file_name = 'event_capacity_lambda.py'
        with zipfile.ZipFile('lambda_function.zip', 'w') as zipf:
            zipf.write(lambda_file_name)
    except Exception:
        pass


# Creates the simple Lambda function using the AWS Lambda client.
# Defines the Lambda function's properties like function name, runtime, role, handler, code, timeout, memory size, and publish settings.
# If the Lambda function is created successfully, logs the success message with the response.
def create_simple_lambda_function():
    try:
        lambda_client = get_lambda_client()  
        response = lambda_client.create_function(
            FunctionName='SimpleLambdaFunction',
            Runtime='python3.8',
            Role='arn:aws:iam::713881783798:role/MyLambdaExecutionRole',
            Handler='index.handler',
            Code={'ZipFile': b'Lambda code here'},
            Timeout=10,
            MemorySize=128,
            Publish=True
        )
        logger.info(f"Lambda function created successfully: {response}")
    except ClientError as e:
        logger.error(f"Error creating Lambda: {e}")

# Writes the Lambda function code for managing event capacity.
# The function checks the event name and updates the remaining capacity in the DynamoDB table.
# If the capacity is full, it returns a message indicating the event is at full capacity.
# If the capacity is not full, it decrements the remaining capacity and updates the table.
# If the capacity reaches 0, it sets the event status to "Full".
def write_event_capacity_lambda_code():
    function_code = '''import json
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
event_table_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']

def lambda_handler(event, context):
    if 'event_name' not in event:
        return {
            'statusCode': 400,
            'body': json.dumps({"message": "Event name is required"})
        }

    event_name_input = event['event_name']
    event_name_input_spaces = event_name_input.replace("_", " ")

    valid_event_names = ['Brisbane River', 'Melbourne Vic', 'Sydney']
    if event_name_input_spaces not in valid_event_names:
        return {
            'statusCode': 400,
            'body': json.dumps({"message": f"Invalid event name: {event_name_input_spaces}"})
        }

    table_name = event_name_input_spaces.replace(" ", "_")
    table = dynamodb.Table(table_name)

    try:
        response = table.get_item(Key={'event_name': event_name_input})
        if 'Item' in response:
            remaining_capacity = response['Item'].get('remaining_capacity')

            # Check if capacity is already "Full"
            if remaining_capacity == 'Full':
                logger.info("Event capacity is already full.")
                return {
                    'statusCode': 200,
                    'body': json.dumps({"message": "Event capacity is full"})
                }

            if isinstance(remaining_capacity, int) and remaining_capacity > 0:
                # Decrement the remaining capacity by 1
                new_remaining_capacity = remaining_capacity - 1
                table.update_item(
                    Key={'event_name': event_name_input},
                    UpdateExpression="SET remaining_capacity = :val",
                    ExpressionAttributeValues={':val': new_remaining_capacity},
                    ReturnValues="ALL_NEW"
                )
                logger.info(f"Updated remaining_capacity to {new_remaining_capacity}")
                return {
                    'statusCode': 200,
                    'body': json.dumps({"message": "Event capacity updated successfully"})
                }

            elif remaining_capacity == 0:
                # Set the event capacity to "Full" if it is 0
                table.update_item(
                    Key={'event_name': event_name_input},
                    UpdateExpression="SET remaining_capacity = :full",
                    ExpressionAttributeValues={':full': 'Full'},
                    ReturnValues="ALL_NEW"
                )
                logger.info("Event capacity is full, updated remaining_capacity to 'Full'")
                return {
                    'statusCode': 200,
                    'body': json.dumps({"message": "Event capacity is now full"})
                }

    except Exception as e:
        logger.error(f"Error updating event capacity: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({"message": "Internal server error"})
        }
    '''

    with open('event_capacity_lambda.py', 'w') as f:
        f.write(function_code)


# Retrieves the description of the Australian Food and Wine Show from an S3 bucket.
# Fetches the text file from the S3 bucket using the specified bucket name and file key.
# Converts the event description (in markdown format) to HTML using the markdown library.
# If successful, returns the event description in HTML format.
# If an error occurs while retrieving the description, returns a generic error message.
def get_australian_food_show_description():
    try:
        response = g.s3.get_object(Bucket=bucket_name, Key=text_file_key)
        event_description = response['Body'].read().decode('utf-8')
        event_description_html = markdown.markdown(event_description)
        return event_description_html
    except Exception:
        return "Error retrieving Australian Food and Wine Show description."

# Checks the authentication of a user by verifying their username and password.
# Retrieves the stored password from the DynamoDB 'admin' table based on the provided username.
# Compares the provided password with the stored password.
# Returns True if the passwords match, indicating successful authentication.
# Returns False if the username is not found or the passwords do not match.
# If any error occurs during the process, returns False as the default.
def check_auth(username, password):
    try:
        table = g.dynamodb.Table('admin')
        response = table.get_item(Key={'login': username})

        if 'Item' in response:
            stored_password = response['Item'].get('password')
            if password == stored_password:
                return True
        return False
    except Exception:
        return False


# Restricts access to a route by checking the provided authorisation credentials.
# If the authorisation is missing, it returns a 401 error with a message indicating missing credentials.
# If the username and password do not match the expected values ('admin' and 'password'), it returns a 401 error with a message indicating invalid credentials.
# If valid credentials are provided, it grants access to the route.
def restrict_access():
    auth = request.authorization
    if not auth:
        print("Authorization headers are missing.")
        return Response('Missing credentials', 401)
    print(f"Received username: {auth.username}")
    if auth.username != 'admin' or auth.password != 'password':
        print("Invalid credentials provided.")
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})


# Manages authentication by returning a 401 error response with a message indicating that authentication is required.
def authenticate():
    logger.debug("Entering authenticate() function")
    return jsonify({"message": "Authentication required"}), 401


# A decorator function to enforce authentication the admin route. 
# Verifies if the user is logged in by looking for 'user' in the session.
# If the user is not logged in, logs a warning and returns an authentication required response (401).
# If the user is logged in, the decorated function is called with the original arguments.
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.debug(f"Session at auth check: {session}")
        if 'user' not in session:
            logger.warning("Unauthorized access attempt detected.")
            return authenticate()  
        logger.debug(f"Authenticated user: {session['user']}")
        return f(*args, **kwargs)
    return decorated


# Manages the updating of event details, including event name, date, location, address, remaining capacity, and description.
# Fetches the current event data from DynamoDB and compares the old and new event date to determine if the capacity is to be updated.
# If the event date is in the past, sets the remaining capacity to "Full".
# Updates the event details in DynamoDB and sends a confirmation email via API Gateway.
@app.route('/update-event', methods=['POST'])
def update_event():
    logger.debug("Received request to update event")  
    event_name = request.form['event_name']
    event_date = request.form['event_date']
    event_location = request.form['event_location']
    event_address = request.form['event_address']
    remaining_capacity = request.form['remaining_capacity']
    event_description = request.form['event_description']
    logger.debug(f"Event details received: {event_name}, {event_date}, {event_location}, {event_address}, {remaining_capacity}, {event_description}")
    table_name = event_name.replace(" ", "_")
    table = g.dynamodb.Table(table_name)
    try:
        logger.debug(f"Fetching event data for {event_name} from DynamoDB")
        response = table.get_item(Key={'event_name': event_name})
        if 'Item' not in response:
            logger.error(f"Event {event_name} not found in DynamoDB")
            flash("Event not found.", "error")
            return redirect(url_for('home'))
        event_data = response['Item']
        old_event_date_str = event_data.get('event_date')
        old_remaining_capacity = event_data.get('remaining_capacity')
        logger.debug(f"Old event date: {old_event_date_str}, Old remaining capacity: {old_remaining_capacity}")
        event_date_object = datetime.strptime(event_date, "%Y-%m-%d")
        current_date = datetime.now()
        if event_date_object < current_date:
            remaining_capacity = 'Full'
        elif old_event_date_str and datetime.strptime(old_event_date_str, "%Y-%m-%d") < current_date and event_date_object >= current_date:
            if not remaining_capacity:
                flash("Please enter a new remaining capacity as the event date is being changed to a future date.", "warning")
                return redirect(url_for('home'))
        logger.debug(f"Updating event details in DynamoDB for {event_name}")
        table.update_item(
            Key={'event_name': event_name},
            UpdateExpression="set event_date = :d, event_location = :l, event_address = :a, remaining_capacity = :r, event_description = :e",
            ExpressionAttributeValues={
                ':d': event_date,
                ':l': event_location,
                ':a': event_address,
                ':r': remaining_capacity,
                ':e': event_description
            },
            ReturnValues="UPDATED_NEW"
        )
        payload = {
            'event_name': event_name,
            'user_email': 'user@example.com',  
            'event_date': event_date,
            'event_location': event_location
        }
        api_url = 'https://t4fo1jnex6.execute-api.us-east-1.amazonaws.com/Prod/SendEmail' 
        logger.debug(f"Invoking API Gateway to send email with payload: {payload}")
        response = requests.post(api_url, json=payload)
        if response.status_code == 200:
            logger.debug(f"Email sent successfully for event {event_name}")
            flash("Event updated successfully! An email has been sent to the user.", "success")
        else:
            logger.error(f"Error sending email for event {event_name}. API response: {response.status_code}")
            flash("Error sending email.", "error")
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Error updating event: {e}")
        flash("Error updating event.", "error")
        return redirect(url_for('home'))


# Calls the AWS Lambda function with a given payload.
# Checks if the event name is included in the payload. 
# Verifies that the Lambda function is active before invoking it.
def invoke_lambda_function(function_name, payload):
    try:
        lambda_client = get_lambda_client()  
        payload = {'event_name': payload['event_name']}

        if 'event_name' not in payload:
            return {"statusCode": 400, "body": json.dumps({"message": "Event name is required"})}
        function_status = check_lambda_function_status(function_name)
        if function_status != 'Active':
            return {"statusCode": 500, "body": json.dumps({"message": "Lambda function is not ready"})}
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        response_payload = response['Payload'].read().decode('utf-8')
        return json.loads(response_payload)
    except ClientError as e:
        logger.error(f"Error invoking Lambda function {function_name}: {e}")
        return {"statusCode": 500, "body": json.dumps({"message": f"Error invoking Lambda function: {str(e)}"})}


# Calls and updates event descriptions for a set of events from DynamoDB.
# The program iterates through a list of event table names and their user-friendly counterparts.
# The Lambda fucntion to update the event capacity is invoked.
# The event details are retrieved from DynamoDB, including event name, date, location, description, address, and remaining capacity.
# A Cloudfront URL is constructed for the event's image based on the event table name.
# Appends the event details (including the image URL) to a list.
def update_event_descriptions():
    event_table_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']
    user_facing_event_names = ['Brisbane River', 'Melbourne Vic', 'Sydney']
    events_list = []
    for event_table_name, user_facing_name in zip(event_table_names, user_facing_event_names):
        try:
            payload = {
                'event_name': user_facing_name
            }
            lambda_response = invoke_lambda_function(update_event_capacity_function_name, payload)
            event_table = g.dynamodb.Table(event_table_name)
            response = event_table.get_item(Key={'event_name': user_facing_name})
            if 'Item' in response:
                image_filename = f"{event_table_name}.jpg"
                cloudfront_image_url = f"https://{cloudfront_domain}/{image_filename}"
                events_list.append({
                    'event_name': response['Item']['event_name'],
                    'event_date': response['Item']['event_date'],
                    'event_location': response['Item']['event_location'],
                    'event_description': response['Item']['event_description'],
                    'event_address': response['Item']['event_address'],
                    'remaining_capacity': response['Item']['remaining_capacity'],
                    'image_url': cloudfront_image_url
                })
        except Exception:
            pass
    return events_list

# Calls a new DynamoDB table for an event with the specified table name.
def create_event_table(table_name):
    try:
        table = g.dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{'AttributeName': 'event_name', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'event_name', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        table.wait_until_exists()
    except Exception as e:
        pass

# Establishes the DynamoDB tables for each event by checking if the table already exists.
# Retrieves event descriptions and iterates over each event.
# If the table for an event does not exist, it creates the table using the event name.
# If the table already exists, the table is loaded.
def create_event_tables():
    events = get_event_descriptions()
    for event in events:
        event_name = event['event_name'].replace(' ', '_')
        try:
            table = g.dynamodb.Table(event_name)
            table.load()
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                create_event_table(event_name)


# Establishes a DynamoDB table for event registrations if it does not already exist.
# The table is named by appending 'Registrations' to the event name..
def create_registration_table_if_not_exists(event_name):
    table_name = f"{event_name.replace(' ', '_')}Registrations"
    try:
        table = g.dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        table.wait_until_exists()
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceInUseException':
            pass

# Establishes a DynamoDB table for event registrations if it does not already exist.
# The table is named by appending 'Registrations' to the event name.
# If the table already exists (ResourceInUseException), it silently ignores the error.
@app.route('/initialize-tables', methods=['GET'])
def initialize_tables():
    try:
        create_event_tables()
        events = get_event_descriptions()
        for event in events:
            event_name = event['event_name'].replace(' ', '_')
            create_registration_table_if_not_exists(event_name)
        
        response = {
            'message': "Event and registration tables initialized successfully.",
            'timestamp': datetime.now().isoformat()
        }  
        return jsonify(response), 200
    except Exception as e:
        return jsonify(message=f"Error initializing tables: {e}"), 500
    
def parse_date(date_str):
    formats = ['%Y-%m-%d', '%d %B %Y']
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Invalid date format: {date_str}")


# A template filter that formats a datetime value into a readable format.
# The filter parses the input value into a date object and formats it as 'day month year' (e.g., '15 November 2024').
@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        date_obj = parse_date(value)
        return date_obj.strftime('%d %B %Y')
    except ValueError:
        return value

# Manages the GET request to retrieve event details for a predefined list of events.
# Retreives the event data from DynamoDB for each event. 
@app.route('/event-details', methods=['GET'])
def event_details():
    events_list = []
    event_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']
    for event_name in event_names:
        event_table = g.dynamodb.Table(event_name)
        try:
            response = event_table.get_item(Key={'event_name': event_name.replace('_', ' ')})
            if 'Item' in response:
                event_data = response['Item']
                event_data['event_date'] = event_data['event_date'].isoformat() if isinstance(event_data.get('event_date'), datetime) else event_data.get('event_date')
                events_list.append(event_data)
        except ClientError:
            pass    
    return jsonify(events=events_list), 200

def send_registration_email(recipient_email, subject, body):
    try:
        g.ses_client.send_email(
            Source=sender_email,  
            Destination={'ToAddresses': [recipient_email]},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Text': {'Data': body, 'Charset': 'UTF-8'}}
            }
        )
    except ClientError as e:
        logger.error(f"Error sending email to {recipient_email}: {e}")
    except NoCredentialsError:
        logger.error("No valid AWS credentials found")

# Retrieves and sanitises event descriptions from DynamoDB for a predefined list of events.
# It fetches the event data from the DynamoDB tables, sanitises the data by providing default values for missing attributes. 
# A list is returned of sanitised event data with attributes such as name, date, location, description, address, remaining capacity, and image URL.
def get_event_descriptions():
    user_facing_event_names = ['Brisbane River', 'Melbourne Vic', 'Sydney']
    events_list = []
    logger.debug("Starting to fetch event descriptions...")
    for event_table_name, user_facing_name in zip(event_table_names, user_facing_event_names):
        logger.debug(f"Preparing to fetch event details for: {user_facing_name} (Table: {event_table_name})")
        try:
            event_table = g.dynamodb.Table(event_table_name)
            logger.debug(f"Fetching from table {event_table_name} with key: {user_facing_name}")
            response = event_table.get_item(Key={'event_name': user_facing_name})
            logger.debug(f"DynamoDB response for {user_facing_name}: {response}")
            if 'Item' in response:
                event = response['Item']
                logger.debug(f"Event {user_facing_name} found in DynamoDB: {event}")  # Log full event details
                sanitized_event = {
                    'event_name': event.get('event_name', 'Unknown'),
                    'event_date': event.get('event_date', 'N/A'),
                    'event_location': event.get('event_location', 'N/A'),
                    'event_description': event.get('event_description', 'N/A'),
                    'event_address': event.get('event_address', 'N/A'),
                    'remaining_capacity': event.get('remaining_capacity', 'N/A'),
                    'image_url': f"https://{cloudfront_domain}/{event_table_name}.jpg"  # Constructing image URL
                }
                logger.debug(f"Sanitized event data: {sanitized_event}")
                events_list.append(sanitized_event)
            else:
                logger.warning(f"Event {user_facing_name} not found in DynamoDB response.")     
        except Exception as e:
            logger.error(f"Error fetching event descriptions for {user_facing_name}: {e}")
            logger.debug(f"Exception details: {str(e)}")
    if events_list:
        logger.debug(f"Successfully fetched events: {events_list}")
    else:
        logger.warning("No events were fetched or the events list is empty.")
    logger.debug(f"Returning events list with {len(events_list)} events.")
    return events_list

# Manages the POST request for event registration.
# The registration details are retrieved from the form (name, email, phone and event name).
# The event data is called from DynamoDB and checks if the event has available capacity.
# Where the event capacity is full, a failure response is returned.
# Verifies if the email is already registered for the event to prevent duplicate registrations.
# If registration is successful, the event's remaining capacity is reduced by updating the event table.
# A confirmation email is sent to the user using the send_registration_email function.
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    event_name = request.form['eventName']
    table_name = f"{event_name.replace(' ', '_')}Registrations"
    event_table = g.dynamodb.Table(event_name.replace(" ", "_"))
    event_response = event_table.get_item(Key={'event_name': event_name})
    if 'Item' in event_response:
        remaining_capacity = event_response['Item'].get('remaining_capacity')
        if isinstance(remaining_capacity, str):
            if remaining_capacity == "Full":
                return jsonify(success=False, message="Event capacity is full."), 400
            else:
                remaining_capacity = int(remaining_capacity)
        if remaining_capacity == 0:
            return jsonify(success=False, message="Event capacity is full."), 400
        registration_table = g.dynamodb.Table(table_name)
        response = registration_table.get_item(Key={'email': email})
        if 'Item' in response:
            return jsonify(success=False, message="Email already registered."), 400
        registration_table.put_item(Item={
            'email': email,
            'name': name,
            'phone': phone,
            'event_name': event_name
        })
        new_remaining_capacity = remaining_capacity - 1
        event_table.update_item(
            Key={'event_name': event_name},
            UpdateExpression="SET remaining_capacity = :val",
            ExpressionAttributeValues={':val': new_remaining_capacity},
            ReturnValues="UPDATED_NEW"
        )
        if new_remaining_capacity == 0:
            event_table.update_item(
                Key={'event_name': event_name},
                UpdateExpression="SET remaining_capacity = :full",
                ExpressionAttributeValues={':full': 'Full'},
                ReturnValues="UPDATED_NEW"
            )
        subject = f"Registration Confirmation for {event_name}"
        body = f"Dear {name},\n\nThank you for registering for {event_name}.\n\nBest regards,\nEvent Team"
        send_registration_email(email, subject, body)
        return jsonify(success=True, message="Registration successful!", remaining_capacity=new_remaining_capacity)
    else:
        return jsonify(success=False, message="Event not found."), 400

# Updates the remaining capacity for an event by invoking the Lambda function responsible for updating event capacity.
# The function constructs a payload with the event name and sends it to the Lambda function.
def update_event_capacity(event_name):
    """Update the remaining capacity for an event by invoking Lambda."""
    payload = {
        'event_name': event_name
    }
    try:
        lambda_client = boto3.client('lambda', region_name='us-east-1')

        response = lambda_client.invoke(
            FunctionName=update_event_capacity_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        lambda_response = json.loads(response['Payload'].read().decode('utf-8'))
        if response['StatusCode'] == 200 and lambda_response.get('statusCode') == 200:
            return "Capacity update successful"
        else:
            return "Error updating capacity"
    except Exception as e:
        logger.error(f"Error invoking Lambda: {str(e)}")
        return "Error invoking Lambda"


# Verifies if the Lambda function exists and creates it if it doesn't.
# If the function does not exist, the program invokes the `create_lambda_function`.
# After creation, it waits for the function to become active.
def check_or_create_lambda_function(function_name):
    try:
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        lambda_client.get_function(FunctionName=function_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            create_lambda_function(function_name)
            start_time = time.time()
            while True:
                function_status = check_lambda_function_status(function_name)
                if function_status == 'Active':
                    break
                elif time.time() - start_time > 90:  
                    logger.error(f"Lambda function {function_name} took too long to activate.")
                    break
                else:
                    time.sleep(5)  
    except Exception as e:
        logger.error(f"Error checking or creating Lambda function {function_name}: {e}")


# Establishes a new Lambda function in AWS.
# If the function name is 'UpdateEventCapacityFunction', it writes and zips the Lambda code for the event capacity update.
# The function then uploads the zipped code to AWS Lambda and sets function properties.
# If the Lambda function creation is successful, it logs the success message.
# If any error occurs during the creation process, it logs the error.
def create_lambda_function(function_name):
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    if function_name == 'UpdateEventCapacityFunction':
        write_event_capacity_lambda_code()
    zip_lambda_function_code()
    with open('lambda_function.zip', 'rb') as f:
        zipped_code = f.read()
    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.8',
            Role='arn:aws:iam::713881783798:role/MyLambdaExecutionRole',  
            Handler='event_capacity_lambda.lambda_handler',
            Code={'ZipFile': zipped_code},
            Timeout=10,
            MemorySize=128,
            Publish=True
        )
        logger.info(f"Lambda function created: {response['FunctionName']}")
    except ClientError as e:
        logger.error(f"Error creating Lambda function: {e}")

# Verifies the status of a Lambda function by querying its configuration.
# The current state of the Lambda function is retrieved and the status logged.
def check_lambda_function_status(function_name):
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        status = response['Configuration']['State']
        logger.info(f"Lambda function {function_name} status: {status}")
        return status
    except ClientError as e:
        logger.error(f"Error checking Lambda function status: {e}")
        return 'Unknown'


# Initializes the setup by checking and creating necessary Lambda functions and updating event capacity.
def initialize_setup():
    try:
        check_or_create_lambda_function(update_event_capacity_function_name)
        for event_name in event_table_names:
            event_name_with_spaces = event_name.replace("_", " ")
            payload = {'event_name': event_name_with_spaces}  
            invoke_lambda_function(update_event_capacity_function_name, payload)
    except Exception as e:
        logger.error(f"Error in initialize_setup: {e}")

# Manages the GET request for the home page.
def invoke_lambda_function_async(function_name, payload):
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='Event',  # Asynchronous invocation
        Payload=json.dumps(payload)
    )

@app.route('/')
def home():
    events = get_event_descriptions()
    for event in events:
        payload = {'event_name': event['event_name']}
        # Invoke Lambda function asynchronously
        invoke_lambda_function_async(update_event_capacity_function_name, payload)
    australian_food_show_description = get_australian_food_show_description()
    return render_template('index.html', 
                           events=events, 
                           event_description=australian_food_show_description)

# The entry point for the application when run as a standalone script.
if __name__ == '__main__':
    try:
        initialize_setup()  
        app.run(debug=True, host='0.0.0.0', port=8000)
    except Exception as e:
        logger.error(f"Error during application startup: {e}")