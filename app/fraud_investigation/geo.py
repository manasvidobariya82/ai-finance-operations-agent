import math
from typing import Dict, Optional, Tuple

# city -> (country, latitude, longitude)
CITIES: Dict[str, Tuple[str, float, float]] = {
    "Mumbai": ("IN", 19.076, 72.878),
    "Delhi": ("IN", 28.704, 77.102),
    "Bengaluru": ("IN", 12.972, 77.595),
    "Hyderabad": ("IN", 17.385, 78.487),
    "Chennai": ("IN", 13.083, 80.271),
    "Kolkata": ("IN", 22.573, 88.364),
    "Pune": ("IN", 18.520, 73.857),
    "Ahmedabad": ("IN", 23.023, 72.571),
    "Jaipur": ("IN", 26.912, 75.787),
    "Lucknow": ("IN", 26.847, 80.947),
    "Kochi": ("IN", 9.931, 76.267),
    "Chandigarh": ("IN", 30.734, 76.779),
    "London": ("GB", 51.507, -0.128),
    "Singapore": ("SG", 1.352, 103.820),
    "Dubai": ("AE", 25.205, 55.271),
    "Amsterdam": ("NL", 52.368, 4.904),
    "Frankfurt": ("DE", 50.110, 8.682),
    "New York": ("US", 40.713, -74.006),
    "Hong Kong": ("HK", 22.320, 114.170),
}

HOME_CITIES = [name for name, (country, _, _) in CITIES.items() if country == "IN"]
FOREIGN_CITIES = [name for name, (country, _, _) in CITIES.items() if country != "IN"]


def country_of(city: Optional[str]) -> Optional[str]:
    return CITIES[city][0] if city in CITIES else None


def distance_km(city_a: Optional[str], city_b: Optional[str]) -> Optional[float]:
    """Great-circle distance between two known cities, or None if either is unknown."""
    if city_a not in CITIES or city_b not in CITIES:
        return None
    _, lat1, lon1 = CITIES[city_a]
    _, lat2, lon2 = CITIES[city_b]
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 6371.0 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
