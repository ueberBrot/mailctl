# Read message bodies independently of attachment payloads

Require bounded retrieval of the selected message body even when attachment payloads make the whole message exceed the wire-fetch limit. This is required for the first useful reading milestone: otherwise a short email with a large PDF could be impossible to summarize. Preserve the limits on headers, MIME structure, parser work and decoded text.

The backend tracer bullet must prove bounded structure and body retrieval without downloading oversized attachment payloads. Whole-message reads remain usable within their verified bounds. Test a short body with an attachment larger than the whole-message fetch limit, plus oversized body and adversarial structure cases. A failed proof requires an explicit scope decision before advertising this behavior.
