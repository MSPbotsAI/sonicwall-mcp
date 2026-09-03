from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No SonicWall credentials. Send the X-Sonicwall-Msw-Api-Key header.",
    False,
)

SERIAL_DESC = "Target firewall's serial number, from sonicwall_list_devices."

# /systemevent/* endpoints answer HTTP 422 naming exactly one missing
# parameter per response if either of these is absent — required, not
# optional, per github.com/GTalksTech/sonicwall-mcp's own comments recording
# that discovery. Neither this requirement nor the values below have been
# independently confirmed against a real tenant.
SYSEVENT_REQUIRED_PARAMS = {"limit": "50", "sort": "time"}
