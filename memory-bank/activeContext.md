# Active context

Physical-goods payment-flow detection expanded:

- Broader static evidence: gateway/WebView deps, payment/checkout symbols, API paths, COD terms
- Optional `payment_flows` declarations (`external_gateway`, `cash_on_delivery`, `offline_payment`, `no_in_app_payment`)
- PASS `external-payment-flow-detected` on static evidence; PASS `payment-flow-declared` / `cash-on-delivery-declared` for honest YAML declarations (not treated as security proof)
- WARNING `external-payment-flow-not-detected` only when neither evidence nor declarations exist
- Never requires Google Play Billing for physical goods

Prior: transaction-type summary visibility; offline billing analyzer; Chicking refinements.
