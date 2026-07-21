# Data contract — regulated-payment-events v2.0.0

Contract fingerprint: fe28205134f6800081e2c7687a95348ec203d395c634ecdb26af2ed69f5594ab

| Field | Rule | Sensitivity | Required | Default | Failure code |
| --- | --- | --- | --- | --- | --- |
| event_id | uuid | operational | true | — | invalid_event_id |
| customer_email | email | direct_identifier | true | — | invalid_customer_email |
| amount | money | financial | true | — | invalid_amount |
| currency | enum | financial | true | — | unsupported_currency |
| event_time | timestamp | operational | true | — | invalid_event_time |
| country | country | quasi_identifier | true | — | invalid_country |
| lawful_basis | enum | governance | true | — | invalid_lawful_basis |
| source_system | enum | operational | false | legacy | unsupported_source_system |

Rows failing a rule are quarantined using the first failure code
in contract order. Direct identifiers are never persisted in clear.
