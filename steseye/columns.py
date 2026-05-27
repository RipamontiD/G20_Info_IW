"""Proportional column layout shared by header and device cards.

Each entry: (id, header_label, relx, relwidth, anchor).
"""

COLUMNS = [
    ("dot",     "",        0.005, 0.020, "w"),
    ("badge",   "TYPE",    0.025, 0.040, "w"),
    ("device",  "DEVICE",  0.070, 0.155, "w"),
    ("address", "ADDRESS", 0.230, 0.135, "w"),
    ("vendor",  "VENDOR",  0.370, 0.220, "w"),
    ("os",      "OS",      0.595, 0.150, "w"),
    ("conf",    "CONF",    0.755, 0.060, "e"),
    ("seen",    "SEEN",    0.820, 0.070, "e"),
]
