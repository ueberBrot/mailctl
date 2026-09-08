# Read message bodies independently of attachment payloads

Retrieve the selected message body independently of attachment payloads, so a large attachment cannot prevent reading a short email. Preserve the limits on headers, MIME structure, parser work, wire bytes, and decoded text.

Use bounded structure and body retrieval when the whole message exceeds the wire-fetch limit. Whole-message reads remain available within that limit.
