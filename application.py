import logging
import json
import os
import zipfile
import time
import markdown
from datetime import datetime
from flask import jsonify

import boto3
import requests
from flask import Flask, Response, render_template, request, jsonify, redirect, session, url_for, flash, g
from functools import wraps
from botocore.exceptions import ClientError, NoCredentialsError


app = Flask(__name__)
app.secret_key = 'your_secret_key'

cloudfront_domain = 'd1ucmletbndp5t.cloudfront.net'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.before_request
def before_request():
    logger.debug(f"Session data at request start: {session}")
    logger.debug(f"Request headers: {request.headers}")
    boto_session = boto3.Session()
    g.s3 = boto_session.client('s3', region_name='us-east-1')
    g.dynamodb = boto_session.resource('dynamodb', region_name='us-east-1')
    g.ses_client = boto_session.client('ses', region_name='us-east-1')
    g.api_gateway_client = boto_session.client('apigateway', region_name='us-east-1')


event_table_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']

bucket_name = 'a3pictures'
text_file_key = 'AustralianFoodandWineShow.txt'

sender_email = "andrewjoyce2022@outlook.com"

update_event_capacity_function_name = 'UpdateEventCapacityFunction'

def get_lambda_client():
    return boto3.client('lambda', region_name='us-east-1')

@app.route('/some_route')
def some_function():
    # Create the Lambda client inside the request context
    lambda_client = get_lambda_client()  # Dynamically get the Lambda client
    # Your logic using lambda_client goes here
    return "Done"

from flask import jsonify


@app.route('/admin/login', methods=['POST'])
def admin_login():
    auth = request.authorization
    if auth and check_auth(auth.username, auth.password):
        # Successful login
        return jsonify({"message": "Login successful"}), 200
    else:
        # Failed login
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Authentication check and session management
    if 'user' not in session:
        if request.method == 'POST':
            auth = request.authorization
            if auth and check_auth(auth.username, auth.password):
                session['user'] = auth.username
                return redirect(url_for('admin'))
            else:
                flash("Invalid credentials. Please try again.", "error")
                return render_template('admin.html')
        return render_template('admin.html')

    # Fetch events and verify data structure
    events = get_event_descriptions()
    print("Fetched events:", events)  # Debugging output to verify the retrieved data

    # Check if events are in a valid list format, otherwise set it to an empty list
    if not events or not isinstance(events, list):
        events = []

    # Sanitize events data to ensure each item is a fully-defined dictionary
    sanitized_events = [event for event in events if isinstance(event, dict)]
    
    # Debugging output for event names
    print("Sanitized Events data:", sanitized_events)
    for event in sanitized_events:
        print(f"Event name: {event.get('event_name', 'No event name found')}")  # Print event name for each event

    # Pass the sanitized events data to the template
    return render_template('admin.html', events=sanitized_events)


def zip_lambda_function_code():
    try:
        lambda_file_name = 'event_capacity_lambda.py'
        with zipfile.ZipFile('lambda_function.zip', 'w') as zipf:
            zipf.write(lambda_file_name)
    except Exception:
        pass

def create_simple_lambda_function():
    try:
        lambda_client = get_lambda_client()  # Get the Lambda client
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

def get_australian_food_show_description():
    try:
        response = g.s3.get_object(Bucket=bucket_name, Key=text_file_key)
        event_description = response['Body'].read().decode('utf-8')
        event_description_html = markdown.markdown(event_description)
        return event_description_html
    except Exception:
        return "Error retrieving Australian Food and Wine Show description."

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

boto_session = boto3.Session()
logger.info(f"Using AWS profile: {boto_session.profile_name}")

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

def authenticate():
    logger.debug("Entering authenticate() function")
    return jsonify({"message": "Authentication required"}), 401

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.debug(f"Session at auth check: {session}")
        if 'user' not in session:
            logger.warning("Unauthorized access attempt detected.")
            return authenticate()  # This returns the "Authentication required" message
        logger.debug(f"Authenticated user: {session['user']}")
        return f(*args, **kwargs)
    return decorated


@app.route('/update-event', methods=['POST'])
def update_event():
    event_name = request.form['event_name']
    event_date = request.form['event_date']
    event_location = request.form['event_location']
    event_address = request.form['event_address']
    remaining_capacity = request.form['remaining_capacity']
    event_description = request.form['event_description']

    table_name = event_name.replace(" ", "_")
    table =g.dynamodb.Table(table_name)

    try:
        response = table.get_item(
            Key={'event_name': event_name}
        )

        if 'Item' not in response:
            flash("Event not found.", "error")
            return redirect(url_for('home'))

        event_data = response['Item']
        old_event_date_str = event_data.get('event_date')
        old_remaining_capacity = event_data.get('remaining_capacity')

        event_date_object = datetime.strptime(event_date, "%Y-%m-%d")
        current_date = datetime.now()

        if event_date_object < current_date:
            remaining_capacity = 'Full'

        elif old_event_date_str and datetime.strptime(old_event_date_str, "%Y-%m-%d") < current_date and event_date_object >= current_date:
            if not remaining_capacity:
                flash("Please enter a new remaining capacity as the event date is being changed to a future date.", "warning")
                return redirect(url_for('home'))

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

        payload = {'event_name': event_name}
        invoke_lambda_function('UpdateEventCapacityFunction', payload)

        flash("Event updated successfully!", "success")
        return redirect(url_for('home'))

    except Exception as e:
        flash("Error updating event.", "error")
        return redirect(url_for('home'))

def invoke_lambda_function(function_name, payload):
    try:
        lambda_client = get_lambda_client()  # Get the Lambda client dynamically
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

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        date_obj = parse_date(value)
        return date_obj.strftime('%d %B %Y')
    except ValueError:
        return value

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
    except ClientError:
        pass
    except NoCredentialsError:
        pass

def get_event_descriptions():
    user_facing_event_names = ['Brisbane River', 'Melbourne Vic', 'Sydney']
    
    events_list = []

    for event_table_name, user_facing_name in zip(event_table_names, user_facing_event_names):
        try:
            payload = {
                'event_name': user_facing_name
            }

            lambda_response = invoke_lambda_function(update_event_capacity_function_name, payload)

            # Use g.dynamodb instead of dynamodb
            event_table = g.dynamodb.Table(event_table_name)  # Accessing dynamodb through g.dynamodb
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

        except Exception as e:
            logger.error(f"Error fetching event descriptions for {user_facing_name}: {e}")
            pass

    return events_list

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    event_name = request.form['eventName']
    table_name = f"{event_name.replace(' ', '_')}Registrations"
    
    # Get the event table from DynamoDB
    event_table = g.dynamodb.Table(event_name.replace(" ", "_"))
    event_response = event_table.get_item(Key={'event_name': event_name})
    
    # Check if the event is found in DynamoDB
    if 'Item' in event_response:
        remaining_capacity = event_response['Item'].get('remaining_capacity')

        # Ensure remaining_capacity is treated as an integer if it's a string
        if isinstance(remaining_capacity, str):
            if remaining_capacity == "Full":
                return jsonify(success=False, message="Event capacity is full."), 400
            else:
                remaining_capacity = int(remaining_capacity)

        # Check if the event is full
        if remaining_capacity == 0:
            return jsonify(success=False, message="Event capacity is full."), 400

        # Check if user is already registered
        registration_table = g.dynamodb.Table(table_name)
        response = registration_table.get_item(Key={'email': email})
        if 'Item' in response:
            return jsonify(success=False, message="Email already registered."), 400

        # Proceed with the registration
        registration_table.put_item(Item={
            'email': email,
            'name': name,
            'phone': phone,
            'event_name': event_name
        })

        # Decrement the remaining capacity by 1
        new_remaining_capacity = remaining_capacity - 1

        # Update the event's remaining capacity in the DynamoDB table
        event_table.update_item(
            Key={'event_name': event_name},
            UpdateExpression="SET remaining_capacity = :val",
            ExpressionAttributeValues={':val': new_remaining_capacity},
            ReturnValues="UPDATED_NEW"
        )

        # If remaining capacity reaches 0, set it to "Full"
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


def update_event_capacity(event_name):
    """Update the remaining capacity for an event by invoking Lambda."""
    payload = {
        'event_name': event_name
    }
    try:
        # Initialize the Lambda client inside the function
        lambda_client = boto3.client('lambda', region_name='us-east-1')

        response = lambda_client.invoke(
            FunctionName=update_event_capacity_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        # Read and decode the response payload
        lambda_response = json.loads(response['Payload'].read().decode('utf-8'))
        
        # Check the response status codes
        if response['StatusCode'] == 200 and lambda_response.get('statusCode') == 200:
            return "Capacity update successful"
        else:
            return "Error updating capacity"
    except Exception as e:
        # Log the error and return a message
        logger.error(f"Error invoking Lambda: {str(e)}")
        return "Error invoking Lambda"

def check_or_create_lambda_function(function_name):
    try:
        # Initialize the Lambda client inside the function
        lambda_client = boto3.client('lambda', region_name='us-east-1')

        # Check if Lambda function exists
        lambda_client.get_function(FunctionName=function_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # If Lambda function doesn't exist, create it
            create_lambda_function(function_name)
            start_time = time.time()
            while True:
                function_status = check_lambda_function_status(function_name)
                if function_status == 'Active':
                    break
                elif time.time() - start_time > 90:  # Increased timeout to 90 seconds
                    logger.error(f"Lambda function {function_name} took too long to activate.")
                    break
                else:
                    time.sleep(5)  # Wait before checking again
    except Exception as e:
        logger.error(f"Error checking or creating Lambda function {function_name}: {e}")


def create_lambda_function(function_name):
    # Initialize the Lambda client inside the function
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
            Role='arn:aws:iam::713881783798:role/MyLambdaExecutionRole',  # Ensure the role has proper permissions
            Handler='event_capacity_lambda.lambda_handler',
            Code={'ZipFile': zipped_code},
            Timeout=10,
            MemorySize=128,
            Publish=True
        )
        logger.info(f"Lambda function created: {response['FunctionName']}")
    except ClientError as e:
        logger.error(f"Error creating Lambda function: {e}")

def check_lambda_function_status(function_name):
    # Initialize the Lambda client inside the function
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    try:
        response = lambda_client.get_function(FunctionName=function_name)
        status = response['Configuration']['State']
        logger.info(f"Lambda function {function_name} status: {status}")
        return status
    except ClientError as e:
        logger.error(f"Error checking Lambda function status: {e}")
        return 'Unknown'


def initialize_setup():
    """Ensure that setup (Lambda and API Gateway creation) is done once."""
    try:
        # This will run during application startup to check and create necessary resources
        check_or_create_lambda_function(update_event_capacity_function_name)
        for event_name in event_table_names:
            event_name_with_spaces = event_name.replace("_", " ")
            payload = {'event_name': event_name_with_spaces}  
            invoke_lambda_function(update_event_capacity_function_name, payload)
    except Exception as e:
        logger.error(f"Error in initialize_setup: {e}")

@app.route('/')
def home():
    # Use g.s3, g.dynamodb, and g.ses_client here, as they are now available inside the request context
    events = get_event_descriptions()
    australian_food_show_description = get_australian_food_show_description()

    return render_template('index.html', 
                           events=events, 
                           event_description=australian_food_show_description)

if __name__ == '__main__':
    try:
        # Initialize the setup before starting the Flask app
        initialize_setup()  # Custom initialization function if needed
        
        # Runs the Flask app
        app.run(debug=True, host='0.0.0.0', port=8000)
    except Exception as e:
        logger.error(f"Error during application startup: {e}")