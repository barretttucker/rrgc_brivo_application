# Brivo User Bulk Update Tool

A Flask-based web application for bulk updating Brivo user data via CSV files. Supports both production and test environments.

## Setup Instructions

### 1. Clone the Repository
```bash
git clone [your-repo-url]
cd [your-repo-directory]
```

### 2. Set Up Python Virtual Environment

#### On Windows:
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate
```

#### On macOS/Linux:
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configuration

#### For Production Mode:
Create a `.env` file in the project root with your Brivo API credentials:
```env
BRIVO_CLIENT_ID=your-client-id
BRIVO_CLIENT_SECRET=your-client-secret
```

#### For Test Mode:
No additional configuration needed - test credentials are pre-configured.

## Running the Application

### Production Mode
```bash
# Single command
python app.py

# The application will be available at http://localhost:5000
```

### Test Mode
1. First, start the mock Brivo API server:
```bash
# In one terminal
python mock_brivo_api.py  # Runs on port 5001
```

2. Then, in another terminal, start the main application in test mode:
```bash
python app.py --test  # Runs on port 5000
```

## CSV Format

Your CSV file should include the following columns:
- `id` (required) - Brivo user ID
- `firstName` (required) - User's first name
- `lastName` (required) - User's last name
- `middleName` (optional) - User's middle name
- `externalId` (optional) - External identifier
- `pin` (optional) - User's PIN
- `effectiveFrom` (optional) - Start date (YYYY-MM-DD format)
- `effectiveTo` (optional) - End date (YYYY-MM-DD format)
- `bleTwoFactorExempt` (optional) - Two-factor exemption (true/false)

Example CSV:
```csv
id,firstName,lastName,middleName,externalId,pin,effectiveFrom,effectiveTo,bleTwoFactorExempt
442211,John,Smith,Robert,EMP123,1234,2024-01-01,2024-12-31,true
442212,Jane,Doe,,EMP124,5678,2024-02-01,2024-12-31,false
```

## Test Environment

The test environment includes a mock Brivo API with:
- OAuth2 authentication flow
- User management endpoints
- In-memory database
- Pre-configured test users (IDs: 442211 and 442212)

## Project Structure
```
your_project/
├── app.py              # Main Flask application
├── config.py           # Configuration for prod/test modes
├── mock_brivo_api.py   # Mock API for testing
├── requirements.txt    # Python dependencies
├── uploads/           # Temporary CSV storage (created automatically)
└── templates/
    ├── base.html      # Base template
    └── index.html     # Main upload page
```

## Development Notes

- The upload directory (`uploads/`) is automatically created and cleaned up
- Files are processed immediately and removed after processing
- All errors during processing are logged and displayed to the user
- The mock API runs on port 5001 to avoid conflicts with the main application
- The main application runs on port 5000

## Troubleshooting

1. If you get an error about missing modules:
   - Ensure you've activated the virtual environment
   - Run `pip install -r requirements.txt` again

2. If the mock API won't start:
   - Check that port 5001 is available
   - Ensure you're running it with Python 3.6+

3. If file uploads fail:
   - Check that the uploads directory exists and is writable
   - Verify your CSV follows the required format
   - Check the file size is under 16MB

## Support

For issues with:
- Brivo API credentials - contact your Brivo administrator
- Application bugs - create an issue in the repository
- CSV format questions - refer to the example above