import json
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
    