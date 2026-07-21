# Data contract — regulated-payment-events v1.0.0

Contract fingerprint: 2d1c4194d51f7c8386fb98ad6c281ee2503e9f08f3aa8fc74d5d659066b62299

| Field | Rule | Sensitivity | Failure code |
| --- | --- | --- | --- |
| event_id | uuid | operational | invalid_event_id |
| customer_email | email | direct_identifier | invalid_customer_email |
| amount | money | financial | invalid_amount |
| currency | enum | financial | unsupported_currency |
| event_time | timestamp | operational | invalid_event_time |
| country | country | quasi_identifier | invalid_country |
| lawful_basis | enum | governance | invalid_lawful_basis |

Rows failing a rule are quarantined using the first failure code
in contract order. Direct identifiers are never persisted in clear.
