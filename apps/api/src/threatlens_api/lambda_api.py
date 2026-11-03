"""Entry point for the API Lambda: API Gateway (HTTP API, payload v2) -> Mangum -> FastAPI.

The gateway's JWT authorizer checks tokens first, but the app checks them again itself
(decision 26), so nothing here trusts the authorizer's claims in the event.
"""

from mangum import Mangum

from threatlens_api.main import app

handler = Mangum(app, lifespan="auto")
