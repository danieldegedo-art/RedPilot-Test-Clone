"""Container for quarantined code. Never imported, never loadable."""
from app.testing.purity.quarantine import refuse_in_pure_mode

refuse_in_pure_mode(__name__)
