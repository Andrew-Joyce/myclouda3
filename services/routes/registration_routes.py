from flask import Blueprint, render_template, request, redirect, url_for, flash
from services.dynamodb_service import register_user_for_event, check_user_registration, dynamodb  # Import dynamodb
import logging

# Define the registration blueprint
registration_routes = Blueprint('registration_routes', __name__)

# Set up logging
logger = logging.getLogger(__name__)

@registration_routes.route('/register/<event_name>', methods=['GET', 'POST'])
def register(event_name):
    """Route to handle registration for an event."""
    try:
        # Fetch event details
        event = get_event_descriptions()  # Modify this function to fetch specific event details if needed
        event = next((e for e in event if e['event_name'] == event_name), None)

        if not event:
            flash("Event not found.", 'error')
            return redirect(url_for('events_routes.events'))  # Redirect if the event doesn't exist

        if request.method == 'POST':
            # Handle registration form submission
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']

            # Check if the user has already registered for the event
            if check_user_registration(event_name, email):
                flash("You have already registered for this event.", 'warning')
                return redirect(url_for('events_routes.event_details', event_name=event_name))  # Redirect to event details page

            # Register the user for the event
            registration_success = register_user_for_event(event_name, name, email, phone)

            if registration_success:
                flash(f"Successfully registered for {event_name}!", 'success')
            else:
                flash("Error registering for the event. Please try again.", 'error')

            return redirect(url_for('events_routes.event_details', event_name=event_name))  # Redirect back to the event details page

        # If it's a GET request, render the registration page for the specific event
        return render_template('register.html', event=event)

    except Exception as e:
        logger.error(f"Error in registration process for {event_name}: {e}")
        flash(f"Error in registration process for {event_name}. Please try again.", 'error')
        return redirect(url_for('events_routes.events'))  # Redirect back to events page in case of error


def get_event_descriptions():
    """Retrieve event descriptions from DynamoDB."""
    event_table_names = ['Brisbane_River', 'Melbourne_Vic', 'Sydney']
    events = []
    try:
        for event_table_name in event_table_names:
            table = dynamodb.Table(event_table_name)
            response = table.scan()  # You can adjust this if you need a different query method
            logger.info(f"Scanned {event_table_name}: {response}")  # Log the scan result
            
            if 'Items' in response and response['Items']:
                event_data = {
                    'event_name': event_table_name.replace("_", " "),  # Adjust for better readability
                    'event_date': response['Items'][0].get('event_date', '2024-12-01'),
                    'event_location': response['Items'][0].get('event_location', 'Location XYZ'),
                    'remaining_capacity': response['Items'][0].get('remaining_capacity', '100'),
                    'event_description': response['Items'][0].get('event_description', 'An amazing event!'),
                }
                events.append(event_data)
            else:
                logger.warning(f"No items found for table {event_table_name}.")
    except Exception as e:
        logger.error(f"Error fetching event descriptions: {e}")
    return events

@registration_routes.route('/confirm-registration/<event_name>/<email>', methods=['GET'])
def confirm_registration(event_name, email):
    """Route to confirm registration for an event."""
    try:
        # Assuming registration confirmation is triggered via a link (like an email verification link)
        if check_user_registration(event_name, email):
            flash(f"Registration confirmed for {event_name}.", 'success')
            return redirect(url_for('events_routes.event_details', event_name=event_name))
        else:
            flash("Invalid confirmation link or registration not found.", 'error')
            return redirect(url_for('events_routes.events'))
    
    except Exception as e:
        logger.error(f"Error confirming registration for {event_name}: {e}")
        flash(f"Error confirming registration for {event_name}. Please try again.", 'error')
        return redirect(url_for('events_routes.events'))  # Redirect back to the events page in case of error


def check_user_registration(event_name, email):
    """Check if a user is already registered for the event."""
    # This function should check DynamoDB for an existing registration using the event_name and email.
    # Example code to check registration:
    try:
        # Assuming a 'registrations' table in DynamoDB for each event
        table_name = f"{event_name.replace(' ', '_')}Registrations"  # Adjust the table name format if needed
        table = dynamodb.Table(table_name)

        response = table.get_item(Key={'email': email})
        if 'Item' in response:
            return True  # User is already registered
        return False  # User is not registered
    except Exception as e:
        logger.error(f"Error checking registration for {event_name} and email {email}: {e}")
        return False
