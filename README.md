# PDF Metadata Tool - License Server

🔐 A Flask-based license validation server for the PDF Metadata Tool application.

## Features

- **Monthly License System**: $9.99/month automatic licensing
- **Hardware Binding**: Licenses locked to specific computers for security
- **Online Validation**: Real-time license verification
- **Admin Panel**: Complete license management interface
- **SQLite Database**: Self-contained database (no external dependencies)
- **Renewal System**: Easy license renewal process

## Deployment

### Deploy to Render (Free)

1. **Fork this repository** to your GitHub account
2. **Connect to Render**:
   - Go to [render.com](https://render.com)
   - Create account and connect GitHub
   - Choose "Web Service" → Connect this repository
3. **Configure Settings**:
   - Language: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python app.py`
   - Instance Type: Free
4. **Add Environment Variables**:
   - `SECRET_KEY`: your-random-secret-key-here
   - `FLASK_ENV`: production
5. **Deploy**: Click "Create Web Service"

Your license server will be available at: `https://your-app-name.onrender.com`

### Deploy to Other Platforms

This Flask app can be deployed to:
- **Heroku**: Use included Procfile
- **Railway**: Connect GitHub repo directly  
- **Fly.io**: Deploy with Docker
- **PythonAnywhere**: Upload files and configure WSGI

## API Endpoints

### License Validation
```
POST /api/validate
Content-Type: application/json

{
  "license_key": "PDFM-XXXX-XXXX-XXXX",
  "hardware_id": "unique-hardware-identifier"
}
```

### Web Interface
- `/` - License purchase page
- `/admin` - Administration panel
- `/purchase` - License creation form
- `/check/{license_key}` - License status check
- `/renew/{license_key}` - License renewal
- `/health` - Health check endpoint

## Database Schema

### Licenses Table
- `license_key`: Unique license identifier (PDFM-XXXX-XXXX-XXXX)
- `hardware_id`: Computer hardware fingerprint
- `customer_email`: Customer email address
- `customer_name`: Customer name (optional)
- `created_date`: License creation timestamp
- `expiry_date`: License expiration timestamp
- `active`: License status (1=active, 0=disabled)
- `payment_id`: Payment processor transaction ID

### Validation Logs Table
- `license_key`: License being validated
- `hardware_id`: Computer attempting validation
- `timestamp`: Validation attempt time
- `status`: Result (VALID, INVALID_KEY, EXPIRED)
- `ip_address`: Client IP address

## Local Development

```bash
# Clone repository
git clone https://github.com/your-username/pdf-license-server.git
cd pdf-license-server

# Install dependencies
pip install -r requirements.txt

# Run development server
python app.py
```

Visit `http://localhost:5000` to test locally.

## Configuration

### Environment Variables
- `SECRET_KEY`: Flask secret key for sessions (required)
- `FLASK_ENV`: Set to "production" for deployment
- `PORT`: Server port (automatically set by hosting platforms)

### Customization
- **Pricing**: Change price in HTML templates and validation logic
- **License Duration**: Modify `timedelta(days=30)` in `create_monthly_license()`
- **License Format**: Update `generate_license_key()` function
- **UI/Styling**: Modify HTML templates with custom CSS

## Security Features

- **Hardware Binding**: Prevents license sharing between computers
- **Encrypted Keys**: License keys use cryptographically secure generation
- **Rate Limiting**: Built-in protection against validation spam
- **Audit Logging**: All validation attempts logged with timestamps
- **SQLite Security**: Database file permissions managed automatically

## Payment Integration

To add real payment processing, integrate with:

### Stripe (Recommended)
```python
import stripe
stripe.api_key = "sk_live_your_stripe_secret_key"

# Add webhook handler for successful payments
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    # Verify webhook signature
    # Create license on successful payment
    # Send license key via email
```

### PayPal
```python
# Use PayPal SDK for payment processing
# Handle IPN (Instant Payment Notifications)
# Create licenses on verified payments
```

## Monitoring & Analytics

- **License Usage**: Track active vs expired licenses in admin panel
- **Validation Patterns**: Monitor validation frequency and failures
- **Customer Insights**: View license creation and renewal trends
- **Health Monitoring**: Use `/health` endpoint for uptime monitoring

## Support & Maintenance

- **Database Backups**: Regularly backup SQLite database file
- **Log Monitoring**: Monitor application logs for errors
- **Performance**: Consider PostgreSQL for high-traffic deployments
- **Updates**: Keep Flask and dependencies updated for security

## License

This software is proprietary. All rights reserved.

## Contact

For technical support or business inquiries:
- Email: support@your-domain.com  
- Website: https://your-website.com

---

**Built with Flask • Deployed on Render • Secured with Hardware Binding**