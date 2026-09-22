"""Synthetic retail-banking data with injected, labelled fraud scenarios - and a scenario simulator
that pushes new live activity through the real-time ingestion path.

The history deliberately includes *legitimate* anomalies (travel, phone upgrades, big one-off
purchases, new payees) so the models can't learn shortcuts like "foreign = fraud".

All names, organisations, account numbers and IP addresses are made up. IPs come from reserved
ranges (RFC 5737 documentation blocks, RFC 6598 carrier-grade NAT) so none point at real hosts.
"""
import ipaddress
import math
import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Optional

from sqlalchemy import func, insert
from sqlalchemy.orm import Session

from app.fraud_investigation import models
from app.fraud_investigation.clock import now
from app.fraud_investigation.geo import FOREIGN_CITIES, HOME_CITIES, country_of

FIRST_NAMES = [
    "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Krishna", "Ishaan", "Rohan",
    "Ananya", "Diya", "Aadhya", "Saanvi", "Kavya", "Isha", "Meera", "Priya", "Nisha", "Pooja",
    "Rahul", "Amit", "Sneha", "Neha", "Karan", "Varun", "Riya", "Arnav", "Kabir", "Zoya",
    "Farhan", "Imran", "Sara", "Harpreet", "Gurpreet", "Lakshmi", "Venkat", "Suresh", "Deepa", "Anil",
    "Sunita", "Manoj", "Rekha", "Nikhil", "Pallavi", "Siddharth", "Aisha", "Joseph", "Maria", "Tenzin",
]
LAST_NAMES = [
    "Sharma", "Verma", "Iyer", "Nair", "Reddy", "Patel", "Shah", "Gupta", "Mehta", "Joshi",
    "Kulkarni", "Desai", "Menon", "Pillai", "Rao", "Singh", "Kaur", "Khan", "Ansari", "Das",
    "Banerjee", "Chatterjee", "Bose", "Agarwal", "Malhotra", "Kapoor", "Chopra", "Bhat", "Hegde", "Fernandes",
]
STREETS = ["MG Road", "Station Road", "Park Street", "Lake View Road", "Temple Street", "Church Road", "Hill Road", "Market Lane"]
BANKS = ["Sahyadri Bank", "Coastal Co-operative Bank", "Metro National Bank", "Deccan Commercial Bank", "Northern Union Bank"]
EMAIL_DOMAINS = ["mailbox.example", "inbox.example", "post.example"]
DISPOSABLE_DOMAINS = ["quickinbox.example", "tempmail.example", "throwaway.example"]

# Authorised push payment scams, and the genuine payments that look like them. Together they are the
# labelled population R014 ("large first payment to a brand-new beneficiary") is measured on; see
# `evaluation.py`.
APP_SCAM = "app_scam"
# How far above the customer's own 90-day average these large payments land.
LARGE_PAYMENT_MULTIPLE = (4.0, 8.0)
SCAM_PAYEE_NAMES = [
    "Quick Returns Investments", "SafeVault Account Services", "Prime Yield Advisory", "Refund Processing Cell",
    "SecureShield Customer Protection", "Golden Harvest Crypto Desk", "Parcel Customs Clearance Office", "Instant Loan Processing",
]
LARGE_PAYEE_NAMES = [
    "Sunrise Residency Rentals", "Pre-Owned Car Bazaar", "Grand Lotus Banquets", "CityCare Multispeciality Hospital",
    "Shree Ganesh Builders", "Horizon Public School", "Lakeside Interiors", "Evergreen Solar Installers",
]
SUPPLIER_NAMES = [
    "Deccan Packaging Supplies", "Metro Office Solutions", "Coastal Freight Carriers", "Konark Industrial Tools",
    "Silverline Printing Press", "Nimbus IT Services", "Riverbend Textiles Wholesale", "Sahyadri Agro Traders",
]

# (name, category, country) - all fictional
MERCHANTS = [
    ("FreshCart Grocers", "grocery", "IN"), ("DailyBasket Supermart", "grocery", "IN"), ("GreenLeaf Organics", "grocery", "IN"),
    ("Voltline Electronics", "electronics", "IN"), ("PixelPoint Digital", "electronics", "IN"), ("GadgetHub Online", "electronics", "IN"),
    ("Highway Fuels", "fuel", "IN"), ("CityPetro", "fuel", "IN"),
    ("SkyRoute Travels", "travel", "IN"), ("TrackLine Rail Bookings", "travel", "IN"), ("Wanderlust Stays", "travel", "IN"),
    ("Spice Route Kitchen", "food", "IN"), ("QuickBite Delivery", "food", "IN"), ("Chai & Co", "food", "IN"),
    ("StyleStreet Fashion", "fashion", "IN"), ("UrbanThreads", "fashion", "IN"),
    ("MediPlus Pharmacy", "pharmacy", "IN"), ("WellCare Chemists", "pharmacy", "IN"),
    ("StarReel Cinemas", "entertainment", "IN"), ("BookNook", "books", "IN"), ("HomeNest Furnishings", "home", "IN"),
    ("CityLight Power", "utilities", "IN"), ("AquaSupply Water Board", "utilities", "IN"),
    ("FiberNet Broadband", "utilities", "IN"), ("TalkMore Mobile", "utilities", "IN"),
    ("ShopSphere Online", "online_retail", "IN"), ("DealDash", "online_retail", "IN"),
    ("GiftVault eCards", "gift_cards", "IN"), ("StreamBox Subscriptions", "digital", "IN"), ("AppCredits Store", "digital", "IN"),
    ("Canal Side Cafe", "food", "NL"), ("Thames Books", "books", "GB"), ("Harbour Lights Dining", "food", "SG"),
    ("Desert Rose Boutique", "fashion", "AE"), ("SkyPort Duty Free", "travel", "AE"), ("Midtown Deli", "food", "US"),
    ("Victoria Harbour Mall", "fashion", "HK"), ("Rhine Electronics", "electronics", "DE"),
]
EVERYDAY_CATEGORIES = {"grocery", "fuel", "food", "fashion", "pharmacy", "entertainment", "books", "home", "online_retail", "travel", "electronics"}
CARD_TESTING_CATEGORIES = {"online_retail", "digital", "gift_cards"}

# Fictional names on the synthetic sanctions list.
SANCTIONED_NAMES = [
    "Northwind Trading FZE", "Blue Meridian Holdings", "Kestrel Import Export LLC", "Obsidian Maritime Ltd",
    "Crimson Delta Commodities", "Silverfin Logistics", "Arkwright Petroleum Services", "Halcyon Metals Trading",
    "Veltra Shipping Corp", "Stonegate Capital Partners FZE", "Iron Lotus General Trading", "Pale Horizon Ventures",
]

PHONE_MODELS = {
    "android": ["Samsung Galaxy S23", "Redmi Note 13", "OnePlus 12", "Pixel 8", "Vivo V29"],
    "ios": ["iPhone 13", "iPhone 14", "iPhone 15"],
    "web": ["Windows · Chrome", "macOS · Safari", "Windows · Edge"],
}

ID_WIDTHS = {"CUST": 4, "ACC": 4, "BEN": 5, "MER": 3, "TX": 6, "ALT": 6}


def format_id(prefix: str, number: int) -> str:
    return f"{prefix}-{number:0{ID_WIDTHS[prefix]}d}"


def next_id(db: Session, model, prefix: str) -> str:
    """Next sequential id; ids are zero-padded so the string max is also the numeric max."""
    latest = db.query(func.max(model.id)).filter(model.id.like(f"{prefix}-%")).scalar()
    return format_id(prefix, int(latest.split("-")[1]) + 1 if latest else 1)


def _ip_pool(*cidrs: str) -> Iterator[str]:
    for cidr in cidrs:
        for host in ipaddress.ip_network(cidr).hosts():
            yield str(host)


@dataclass
class SyntheticConfig:
    customers: int = 200
    days: int = 90
    seed: int = 7
    end: Optional[datetime] = None  # default: start of yesterday


@dataclass
class _Cust:
    id: str
    account_id: str
    account_number: str
    name: str
    home_city: str
    median: float
    rate: float
    mean_hour: float
    primary_device: str
    laptop_device: Optional[str]
    home_ip: str
    mobile_ip: str
    opened_at: datetime
    segment: str = "mass"
    beneficiaries: List[str] = field(default_factory=list)
    billers: List[str] = field(default_factory=list)


@dataclass
class _Attacker:
    device: str
    ip: str
    city: str


class SyntheticWorld:
    def __init__(self, cfg: SyntheticConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.end = cfg.end or now().replace(hour=0, minute=0, second=0) - timedelta(days=1)
        self.start = self.end - timedelta(days=cfg.days)
        self.rows: Dict[str, List[dict]] = {
            name: []
            for name in (
                "customers", "accounts", "devices", "counterparties", "transactions",
                "account_events", "watchlist_entries", "ip_reputation",
            )
        }
        self.counters: Dict[str, int] = {}
        self.residential_ips = _ip_pool("198.51.100.0/24", "203.0.113.0/25", "172.16.0.0/16")
        self.hotel_ips = _ip_pool("203.0.113.128/25")
        self.attacker_ips = _ip_pool("192.0.2.0/24")
        self.cgnat_ips = [f"100.64.{i // 250}.{i % 250 + 1}" for i in range(30)]
        self.merchants: Dict[str, dict] = {}
        self.customers: List[_Cust] = []

    # --- id / row helpers ----------------------------------------------------------------------

    def _id(self, prefix: str) -> str:
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        return format_id(prefix, self.counters[prefix])

    def _account_number(self) -> str:
        return "".join(str(self.rng.randint(0, 9)) for _ in range(12))

    def _name(self) -> str:
        return f"{self.rng.choice(FIRST_NAMES)} {self.rng.choice(LAST_NAMES)}"

    def device(self, platform: str, first_seen: datetime) -> str:
        device_id = f"DEV-{self.rng.getrandbits(32):08x}"
        self.rows["devices"].append(
            {"id": device_id, "platform": platform, "model": self.rng.choice(PHONE_MODELS[platform]), "first_seen": first_seen}
        )
        return device_id

    def beneficiary(self, name: str, account_number: Optional[str] = None, bank: Optional[str] = None) -> str:
        cp_id = self._id("BEN")
        self.rows["counterparties"].append(
            {
                "id": cp_id, "kind": "beneficiary", "name": name,
                "account_number": account_number or self._account_number(),
                "bank": bank or self.rng.choice(BANKS), "country": "IN", "category": None, "status": "active",
            }
        )
        return cp_id

    def ip_reputation(self, ip: str, risk: int, usage: str, city: str, isp: str) -> None:
        self.rows["ip_reputation"].append(
            {
                "ip_address": ip, "risk_score": risk, "usage_type": usage, "isp": isp, "city": city,
                "country": country_of(city), "source": "Synthetic IP Reputation Feed (demo)", "last_updated": self.end,
            }
        )

    def txn(
        self, c: _Cust, ts: datetime, amount: float, txn_type: str, counterparty: str, method: str, channel: str,
        device: Optional[str], ip: Optional[str], city: str, is_fraud: bool = False, scenario: Optional[str] = None,
    ) -> None:
        self.rows["transactions"].append(
            {
                "id": None, "account_id": c.account_id, "customer_id": c.id, "counterparty_id": counterparty,
                "amount": round(amount, 2), "currency": "INR", "timestamp": ts.replace(microsecond=0),
                "txn_type": txn_type, "payment_method": method, "channel": channel, "device_id": device,
                "ip_address": ip, "city": city, "country": country_of(city), "status": "completed",
                "is_fraud": is_fraud, "scenario": scenario, "ingested_at": ts.replace(microsecond=0),
            }
        )

    def event(
        self, c: _Cust, event_type: str, ts: datetime, device: Optional[str], ip: Optional[str], city: str,
        details: Optional[dict] = None, scenario: Optional[str] = None,
    ) -> None:
        self.rows["account_events"].append(
            {
                "customer_id": c.id, "account_id": c.account_id, "event_type": event_type,
                "timestamp": ts.replace(microsecond=0), "device_id": device, "ip_address": ip, "city": city,
                "country": country_of(city), "details": details or {}, "scenario": scenario,
            }
        )

    def login(self, c: _Cust, ts: datetime, device: str, ip: str, city: str, scenario: Optional[str] = None) -> None:
        if self.rng.random() < 0.02:
            self.event(c, "login_failed", ts - timedelta(seconds=40), device, ip, city, {"reason": "wrong_password"}, scenario)
        self.event(c, "login_success", ts, device, ip, city, {"session_seconds": self.rng.randint(60, 900)}, scenario)

    # --- population ----------------------------------------------------------------------------

    def build_merchants(self) -> None:
        for name, category, country in MERCHANTS:
            mer_id = self._id("MER")
            self.merchants[mer_id] = {"name": name, "category": category, "country": country}
            self.rows["counterparties"].append(
                {
                    "id": mer_id, "kind": "merchant", "name": name, "account_number": None, "bank": None,
                    "country": country, "category": category, "status": "active",
                }
            )

    def merchants_where(self, categories=None, country: str = "IN") -> List[str]:
        return [
            mid for mid, m in self.merchants.items()
            if m["country"] == country and (categories is None or m["category"] in categories)
        ]

    def add_customer(
        self, created_at: datetime, segment: Optional[str] = None, kyc_status: str = "verified",
        email_domain: Optional[str] = None, phone: Optional[str] = None, address: Optional[str] = None,
        home_city: Optional[str] = None,
    ) -> _Cust:
        rng = self.rng
        segment = segment or rng.choices(["mass", "affluent", "business"], [0.6, 0.3, 0.1])[0]
        median = {"mass": rng.uniform(800, 3000), "affluent": rng.uniform(4000, 12000), "business": rng.uniform(10000, 35000)}[segment]
        name = self._name()
        home_city = home_city or rng.choice(HOME_CITIES)
        cust_id, acc_id = self._id("CUST"), self._id("ACC")
        slug = name.lower().replace(" ", ".")
        self.rows["customers"].append(
            {
                "id": cust_id, "full_name": name,
                "email": f"{slug}{rng.randint(1, 999)}@{email_domain or rng.choice(EMAIL_DOMAINS)}",
                "phone": phone or f"+91 9{rng.randint(100000000, 999999999)}",
                "address": address or f"{rng.randint(1, 250)} {rng.choice(STREETS)}, {home_city}",
                "home_city": home_city, "home_country": "IN", "segment": segment, "kyc_status": kyc_status,
                "kyc_document": rng.choice(["Passport", "National ID card", "Driving licence"]),
                "kyc_verified_at": created_at + timedelta(days=1) if kyc_status == "verified" else None,
                "created_at": created_at, "prior_fraud_cases": 0,
            }
        )
        account_number = self._account_number()
        self.rows["accounts"].append(
            {"id": acc_id, "customer_id": cust_id, "account_number": account_number, "opened_at": created_at, "currency": "INR", "status": "active"}
        )
        home_ip = next(self.residential_ips)
        self.ip_reputation(home_ip, rng.randint(0, 10), "residential", home_city, "HomeFiber ISP") if rng.random() < 0.5 else None
        c = _Cust(
            id=cust_id, account_id=acc_id, account_number=account_number, name=name, home_city=home_city,
            median=median, rate=rng.uniform(0.4, 1.4), mean_hour=rng.uniform(10, 19),
            primary_device=self.device(rng.choices(["android", "ios"], [0.7, 0.3])[0], created_at),
            laptop_device=self.device("web", created_at) if rng.random() < 0.4 else None,
            home_ip=home_ip, mobile_ip=rng.choice(self.cgnat_ips), opened_at=created_at, segment=segment,
        )
        c.beneficiaries = [self.beneficiary(self._name()) for _ in range(rng.randint(2, 6))]
        c.billers = rng.sample(self.merchants_where({"utilities"}), rng.randint(1, 2))
        self.customers.append(c)
        return c

    # --- everyday activity ---------------------------------------------------------------------

    def _hour(self, c: _Cust) -> float:
        return min(23.5, max(7.0, self.rng.gauss(c.mean_hour, 2.5)))

    def everyday(self, c: _Cust, start: datetime, end: datetime, device_switch: Optional[tuple] = None) -> None:
        rng = self.rng
        day = start.replace(hour=0, minute=0, second=0)
        while day < end:
            device = c.primary_device
            if device_switch and day >= device_switch[0]:
                device = device_switch[1]
            if day.day == 5 or (day.day == 1 and day.month == 2):
                for biller in c.billers:
                    ts = day + timedelta(hours=self._hour(c))
                    if start <= ts < end:
                        self.login(c, ts - timedelta(minutes=3), device, c.home_ip, c.home_city)
                        self.txn(c, ts, c.median * rng.uniform(0.6, 1.2), "bill_payment", biller, "upi", "mobile_app", device, c.home_ip, c.home_city)
            for _ in range(self._poisson(c.rate)):
                ts = day + timedelta(hours=self._hour(c))
                if not (start <= ts < end):
                    continue
                ip = c.home_ip if rng.random() < 0.7 else c.mobile_ip
                roll = rng.random()
                if roll < 0.3:
                    merchant = rng.choice(self.merchants_where(EVERYDAY_CATEGORIES))
                    self.txn(c, ts, rng.lognormvariate(0, 0.8) * c.median, "card_purchase", merchant, "card", "pos", None, None, c.home_city)
                elif roll < 0.62:
                    merchant = rng.choice(self.merchants_where(EVERYDAY_CATEGORIES))
                    dev = c.laptop_device if c.laptop_device and rng.random() < 0.4 else device
                    self.login(c, ts - timedelta(minutes=rng.randint(1, 6)), dev, ip, c.home_city)
                    self.txn(c, ts, rng.lognormvariate(0, 0.8) * c.median, "card_purchase", merchant, "card", "web" if dev == c.laptop_device else "mobile_app", dev, ip, c.home_city)
                else:
                    self.login(c, ts - timedelta(minutes=rng.randint(1, 6)), device, ip, c.home_city)
                    method = rng.choices(["upi", "imps", "neft"], [0.6, 0.3, 0.1])[0]
                    amount = round(rng.lognormvariate(0, 0.7) * c.median * 1.8)
                    self.txn(c, ts, amount, "transfer", rng.choice(c.beneficiaries), method, "mobile_app", device, ip, c.home_city)
            day += timedelta(days=1)

    def _poisson(self, lam: float) -> int:
        count, threshold, p = 0, pow(2.718281828, -lam), 1.0
        while True:
            p *= self.rng.random()
            if p <= threshold:
                return count
            count += 1

    def _day_in_history(self, min_offset_days: int = 15) -> datetime:
        span = max(1, self.cfg.days - min_offset_days - 2)
        return self.start + timedelta(days=min_offset_days + self.rng.randrange(span))

    def _prior_average(self, c: _Cust, ts: datetime) -> Optional[float]:
        """The customer's 90-day average transaction amount as of `ts`, or None with no baseline.

        Uses exactly the rows and window `features.py` uses for `amount_vs_customer_avg` - every
        transaction type, strictly before `ts`, at least three of them - so a scenario can place a
        payment at a known multiple of it. The rule under test compares against this number, not
        against the median the customer was generated from, and the two differ a lot.
        """
        window_start = ts - timedelta(days=90)
        amounts = [
            row["amount"] for row in self.rows["transactions"]
            if row["customer_id"] == c.id and window_start <= row["timestamp"] < ts
        ]
        return statistics.fmean(amounts) if len(amounts) >= 3 else None

    def _amount_at_multiple(self, c: _Cust, ts: datetime, low: float, high: float) -> Optional[float]:
        """A round amount at a random multiple in [low, high) of the customer's 90-day average.

        Rounded *up* to the next ₹100, so the realised multiple never falls below the one drawn.
        """
        average = self._prior_average(c, ts)
        if average is None:
            return None
        return math.ceil(self.rng.uniform(low, high) * average / 100) * 100

    def _large_first_payment(
        self, c: _Cust, payee_names: List[str], scenario: str, is_fraud: bool,
        device: Optional[str] = None, channel: str = "mobile_app", method: Optional[str] = None,
    ) -> bool:
        """A payee added and paid 4-8x the customer's average within minutes, from the customer's own
        device, home connection and city, at their usual time of day, with credentials untouched.

        This is the shape R014 fires on, shared by the APP scam and its legitimate look-alikes so
        that the label is the only thing that differs. Returns False, injecting nothing, when the
        customer has no baseline for the payment to be unusual against.
        """
        rng = self.rng
        device = device or c.primary_device
        ts = (self._day_in_history(30) + timedelta(hours=self._hour(c))).replace(microsecond=0)
        amount = self._amount_at_multiple(c, ts, *LARGE_PAYMENT_MULTIPLE)
        if amount is None:
            return False
        payee = self.beneficiary(rng.choice(payee_names))
        self.event(
            c, "login_success", ts - timedelta(minutes=rng.randint(10, 30)), device, c.home_ip, c.home_city,
            {"session_seconds": rng.randint(600, 1800)}, scenario,
        )
        self.event(
            c, "beneficiary_added", ts - timedelta(minutes=rng.randint(3, 8)), device, c.home_ip, c.home_city,
            {"counterparty_id": payee}, scenario,
        )
        self.txn(
            c, ts, amount, "transfer", payee, method or rng.choice(["imps", "neft"]), channel, device,
            c.home_ip, c.home_city, is_fraud, scenario,
        )
        return True

    # --- legitimate anomalies ------------------------------------------------------------------

    def legit_travel(self, c: _Cust) -> None:
        rng = self.rng
        city = rng.choice([cty for cty in FOREIGN_CITIES if self.merchants_where(None, country_of(cty))])
        country = country_of(city)
        hotel_ip = next(self.hotel_ips)
        self.ip_reputation(hotel_ip, rng.randint(15, 30), "hotel", city, "Hospitality WiFi Networks")
        day = self._day_in_history(20)
        for offset in range(rng.randint(3, 6)):
            ts = day + timedelta(days=offset, hours=self._hour(c))
            self.event(c, "login_success", ts - timedelta(minutes=4), c.primary_device, hotel_ip, city, {"session_seconds": 300}, "legit_travel")
            if offset == 0:
                self.event(c, "mfa_success", ts - timedelta(minutes=3), c.primary_device, hotel_ip, city, {"mfa_device": "known", "method": "app_push"}, "legit_travel")
            for _ in range(rng.randint(1, 3)):
                merchant = rng.choice(self.merchants_where(None, country))
                self.txn(c, ts + timedelta(minutes=rng.randint(0, 240)), c.median * rng.uniform(1.5, 4), "card_purchase", merchant, "card", "mobile_app", c.primary_device, hotel_ip, city, scenario="legit_travel")

    def legit_new_device(self, c: _Cust) -> Optional[tuple]:
        day = self._day_in_history(15)
        ts = day + timedelta(hours=self._hour(c))
        new_device = self.device(self.rng.choice(["android", "ios"]), ts)
        self.event(c, "mfa_success", ts - timedelta(minutes=2), c.primary_device, c.home_ip, c.home_city, {"mfa_device": "known", "method": "app_push"}, "legit_new_device")
        self.event(c, "device_added", ts - timedelta(minutes=1), new_device, c.home_ip, c.home_city, {"verified_with": "existing_device"}, "legit_new_device")
        self.event(c, "login_success", ts, new_device, c.home_ip, c.home_city, {"session_seconds": 420}, "legit_new_device")
        merchant = self.rng.choice(self.merchants_where(EVERYDAY_CATEGORIES))
        self.txn(c, ts + timedelta(minutes=5), c.median * self.rng.uniform(0.5, 2), "card_purchase", merchant, "card", "mobile_app", new_device, c.home_ip, c.home_city, scenario="legit_new_device")
        return (day + timedelta(days=1), new_device)

    def legit_password_reset(self, c: _Cust) -> None:
        ts = self._day_in_history(10) + timedelta(hours=self._hour(c))
        self.event(c, "password_reset", ts, c.primary_device, c.home_ip, c.home_city, {"channel": "email_link"}, "legit_password_reset")
        self.event(c, "login_success", ts + timedelta(minutes=2), c.primary_device, c.home_ip, c.home_city, {"session_seconds": 200}, "legit_password_reset")
        self.txn(c, ts + timedelta(minutes=6), round(c.median * self.rng.uniform(0.8, 2)), "transfer", self.rng.choice(c.beneficiaries), "upi", "mobile_app", c.primary_device, c.home_ip, c.home_city, scenario="legit_password_reset")

    def legit_large_purchase(self, c: _Cust) -> None:
        ts = self._day_in_history(20) + timedelta(hours=self._hour(c))
        merchant = self.rng.choice(self.merchants_where({"electronics", "travel", "home"}))
        self.login(c, ts - timedelta(minutes=3), c.primary_device, c.home_ip, c.home_city, "legit_large_purchase")
        self.txn(c, ts, c.median * self.rng.uniform(5, 12), "card_purchase", merchant, "card", "mobile_app", c.primary_device, c.home_ip, c.home_city, scenario="legit_large_purchase")

    def legit_new_beneficiary(self, c: _Cust) -> None:
        ts = self._day_in_history(10) + timedelta(hours=self._hour(c))
        payee = self.beneficiary(self._name())
        c.beneficiaries.append(payee)
        self.login(c, ts - timedelta(minutes=6), c.primary_device, c.home_ip, c.home_city, "legit_new_beneficiary")
        self.event(c, "beneficiary_added", ts - timedelta(minutes=4), c.primary_device, c.home_ip, c.home_city, {"counterparty_id": payee}, "legit_new_beneficiary")
        self.txn(c, ts, round(c.median * self.rng.uniform(1, 3)), "transfer", payee, "imps", "mobile_app", c.primary_device, c.home_ip, c.home_city, scenario="legit_new_beneficiary")

    def legit_large_new_payee(self, c: _Cust) -> bool:
        """A genuine large first payment to a new payee: a rental deposit, a used car, a wedding
        venue, a hospital bill.

        Built exactly like `app_scam` - same timing, device, location and amount band - so apart from
        the payee's name only the label differs. Most first payments to a new payee are this, and it
        is what sets R014's precision.
        """
        return self._large_first_payment(c, LARGE_PAYEE_NAMES, "legit_large_new_payee", False)

    def legit_business_supplier(self, c: _Cust) -> bool:
        """A business customer settling a first invoice with a new supplier, by NEFT, from the office
        laptop where there is one. Large and to a brand-new payee, so R014 fires on it too."""
        return self._large_first_payment(
            c, SUPPLIER_NAMES, "legit_business_supplier", False,
            device=c.laptop_device, channel="web" if c.laptop_device else "mobile_app", method="neft",
        )

    def legit_large_known_payee(self, c: _Cust) -> bool:
        """A transfer as unusually large as a scam's, but to someone the customer has paid before -
        a year's rent up front, a relative's tuition. Size alone is not the signal."""
        rng = self.rng
        s = "legit_large_known_payee"
        ts = (self._day_in_history(30) + timedelta(hours=self._hour(c))).replace(microsecond=0)
        paid_before = sorted({
            row["counterparty_id"] for row in self.rows["transactions"]
            if row["customer_id"] == c.id and row["txn_type"] == "transfer" and row["timestamp"] < ts
        })
        amount = self._amount_at_multiple(c, ts, *LARGE_PAYMENT_MULTIPLE)
        if amount is None or not paid_before:
            return False
        self.event(c, "login_success", ts - timedelta(minutes=rng.randint(5, 15)), c.primary_device, c.home_ip, c.home_city, {"session_seconds": rng.randint(200, 900)}, s)
        self.txn(c, ts, amount, "transfer", rng.choice(paid_before), rng.choice(["imps", "neft"]), "mobile_app", c.primary_device, c.home_ip, c.home_city, scenario=s)
        return True

    # --- fraud ---------------------------------------------------------------------------------

    def attacker_pool(self, count: int, cities: List[str], usages: List[str], listed_share: float) -> List[_Attacker]:
        pool = []
        for i in range(count):
            city = cities[i % len(cities)]
            ip = next(self.attacker_ips)
            if self.rng.random() < listed_share:
                self.ip_reputation(ip, self.rng.randint(72, 96), self.rng.choice(usages), city, "Anonymous Hosting Ltd")
            pool.append(_Attacker(self.device(self.rng.choice(["android", "ios", "web"]), self.start), ip, city))
        return pool

    def account_takeover(self, c: _Cust, attacker: _Attacker, mule_payees: List[str], t0: Optional[datetime] = None) -> None:
        rng = self.rng
        s = "account_takeover"
        if t0 is None:
            day = self._day_in_history(20)
            hour = rng.uniform(1, 4.5) if rng.random() < 0.7 else rng.uniform(9, 22)
            t0 = day + timedelta(hours=hour)
        a = attacker
        t = t0 - timedelta(minutes=rng.randint(30, 45))
        for _ in range(rng.randint(3, 6)):
            self.event(c, "login_failed", t, a.device, a.ip, a.city, {"reason": "wrong_password"}, s)
            t += timedelta(seconds=rng.randint(20, 90))
        self.event(c, "password_reset", t0 - timedelta(minutes=18), a.device, a.ip, a.city, {"channel": "sms_otp"}, s)
        self.event(c, "login_success", t0 - timedelta(minutes=16), a.device, a.ip, a.city, {"session_seconds": 1500}, s)
        if rng.random() < 0.4:
            self.event(c, "mfa_method_changed", t0 - timedelta(minutes=14), a.device, a.ip, a.city, {"new_method": "sms", "old_method": "app_push"}, s)
        if rng.random() < 0.3:
            self.event(c, "profile_updated", t0 - timedelta(minutes=13), a.device, a.ip, a.city, {"field": "phone"}, s)
        self.event(c, "device_added", t0 - timedelta(minutes=12), a.device, a.ip, a.city, {"verified_with": "sms_otp"}, s)
        payee = rng.choice(mule_payees)
        self.event(c, "beneficiary_added", t0 - timedelta(minutes=8), a.device, a.ip, a.city, {"counterparty_id": payee}, s)
        for i in range(rng.randint(1, 3)):
            amount = min(450000, round(c.median * rng.uniform(10, 30), -3))
            self.txn(c, t0 + timedelta(minutes=3 * i), amount, "transfer", payee, "imps", "mobile_app", a.device, a.ip, a.city, True, s)

    def card_testing(self, c: _Cust, attacker: _Attacker, t0: Optional[datetime] = None) -> None:
        rng = self.rng
        s = "card_testing"
        if t0 is None:
            t0 = self._day_in_history(15) + timedelta(hours=rng.uniform(0, 24))
        t = t0
        for _ in range(rng.randint(5, 9)):
            merchant = rng.choice(self.merchants_where(CARD_TESTING_CATEGORIES))
            self.txn(c, t, rng.uniform(20, 350), "card_purchase", merchant, "card", "web", attacker.device, attacker.ip, attacker.city, True, s)
            t += timedelta(seconds=rng.randint(40, 150))
        for _ in range(rng.randint(1, 2)):
            merchant = rng.choice(self.merchants_where({"electronics", "gift_cards"}))
            self.txn(c, t, rng.uniform(15000, 60000), "card_purchase", merchant, "card", "web", attacker.device, attacker.ip, attacker.city, True, s)
            t += timedelta(minutes=rng.randint(2, 6))

    def app_scam(self, c: _Cust) -> bool:
        """Authorised push payment scam: the customer is talked into sending the money themselves.

        Someone posing as the bank's fraud team, an investment adviser or a customs office gets the
        customer to add a new payee and move a large sum to it. Everything an attacker would trip is
        absent - own phone, home connection and city, usual hours, credentials untouched - and what
        is left is a first payment to a brand-new beneficiary at 4-8x the customer's normal amount.
        These are the only positives R014 has.
        """
        return self._large_first_payment(c, SCAM_PAYEE_NAMES, APP_SCAM, True)

    def mule_ring(self, size: int) -> dict:
        """Synthetic identities sharing devices, IPs and identity details, cashing out to a shared
        pair of external accounts."""
        rng = self.rng
        devices = [self.device("android", self.start), self.device("web", self.start)]
        ips = [next(self.attacker_ips), next(self.attacker_ips)]
        self.ip_reputation(ips[0], rng.randint(50, 70), "datacenter", "Mumbai", "CloudNine Hosting")
        shared_phone = f"+91 9{rng.randint(100000000, 999999999)}"
        shared_address = f"{rng.randint(1, 99)} {rng.choice(STREETS)}, Mumbai"
        cashout = [self.beneficiary(f"{self._name()} Enterprises"), self.beneficiary(self._name())]
        members = []
        for i in range(size):
            created = self.end - timedelta(days=rng.randint(25, 70))
            c = self.add_customer(
                created, segment="mass", kyc_status=rng.choice(["verified", "pending"]),
                email_domain=rng.choice(DISPOSABLE_DOMAINS) if rng.random() < 0.6 else None,
                phone=shared_phone if i % 3 == 0 else None, address=shared_address if i % 2 == 0 else None,
                home_city="Mumbai",
            )
            c.primary_device, c.home_ip = devices[i % 2], ips[i % 2]
            members.append(c)
            # Other customers can pay this account as an ordinary "beneficiary": entity resolution
            # in the graph links the two.
            c.billers = [self.beneficiary(c.name, account_number=c.account_number, bank="Metro National Bank")]
        return {"members": members, "devices": devices, "ips": ips, "cashout": cashout, "inbound_payees": [m.billers[0] for m in members]}

    def ring_activity(self, ring: dict) -> None:
        rng = self.rng
        for c in ring["members"]:
            start = max(c.opened_at, self.start)
            for _ in range(rng.randint(1, 3)):
                ts = start + timedelta(hours=rng.uniform(24, max(25, (self.end - start).total_seconds() / 3600 - 1)))
                merchant = rng.choice(self.merchants_where({"grocery", "food"}))
                self.login(c, ts - timedelta(minutes=2), c.primary_device, c.home_ip, c.home_city)
                self.txn(c, ts, rng.uniform(150, 900), "card_purchase", merchant, "card", "mobile_app", c.primary_device, c.home_ip, c.home_city)
            for _ in range(rng.randint(3, 6)):
                ts = start + timedelta(hours=rng.uniform(48, max(49, (self.end - start).total_seconds() / 3600 - 1)))
                device = rng.choice(ring["devices"])
                ip = rng.choice(ring["ips"])
                self.event(c, "login_success", ts - timedelta(minutes=3), device, ip, "Mumbai", {"session_seconds": 180}, "mule_cashout")
                amount = round(rng.uniform(25000, 150000), -2)
                self.txn(c, ts, amount, "transfer", rng.choice(ring["cashout"]), "imps", "mobile_app", device, ip, "Mumbai", True, "mule_cashout")

    # --- intelligence --------------------------------------------------------------------------

    def watchlists(self, ring: dict, ato_pool: List[_Attacker], card_pool: List[_Attacker]) -> None:
        def entry(list_name, entity_type, value, source, severity, reason):
            self.rows["watchlist_entries"].append(
                {"list_name": list_name, "entity_type": entity_type, "value": value, "source": source, "severity": severity, "reason": reason, "added_at": self.start}
            )

        for name in SANCTIONED_NAMES:
            entry("sanctions", "name", name, "Synthetic Sanctions List (demo)", "high", "Sanctioned entity")
        for domain in DISPOSABLE_DOMAINS:
            entry("disposable_email", "email_domain", domain, "Disposable Email Domain Feed (demo)", "medium", "Disposable email provider")
        cashout_number = next(r["account_number"] for r in self.rows["counterparties"] if r["id"] == ring["cashout"][0])
        entry("internal_blocklist", "account_number", cashout_number, "Internal fraud team", "high", "Confirmed mule account from a closed case")
        entry("internal_blocklist", "device", ato_pool[0].device, "Internal fraud team", "high", "Device used in confirmed account takeover")
        entry("internal_blocklist", "ip", card_pool[0].ip, "Internal fraud team", "high", "IP used in confirmed card-testing attack")

    # --- generation ----------------------------------------------------------------------------

    def generate(self) -> None:
        rng = self.rng
        n = self.cfg.customers
        self.build_merchants()
        for cgnat in self.cgnat_ips:
            self.ip_reputation(cgnat, 10, "mobile_cgnat", rng.choice(HOME_CITIES), "Mobile Carrier CGNAT")

        normal = []
        for _ in range(n):
            if rng.random() < 0.06:
                created = self.end - timedelta(days=rng.randint(20, 80))  # legitimately new customers
            else:
                created = self.start - timedelta(days=rng.randint(200, 3000))
            normal.append(self.add_customer(created, kyc_status="verified" if rng.random() < 0.97 else "pending"))

        ato_pool = self.attacker_pool(4, ["Amsterdam", "Frankfurt", "Singapore", "Hong Kong"], ["vpn", "tor", "datacenter"], 0.7)
        card_pool = self.attacker_pool(3, ["Mumbai", "Delhi", "London"], ["datacenter", "vpn"], 0.6)
        rings = [self.mule_ring(max(4, n // 30)) for _ in range(2)]
        mule_payees = rings[0]["inbound_payees"] + rings[1]["inbound_payees"]

        shuffled = normal[:]
        rng.shuffle(shuffled)
        k = max(1, n // 12)
        ato_victims = shuffled[: max(4, n // 14)]
        card_victims = shuffled[len(ato_victims) : len(ato_victims) + max(3, n // 20)]
        others = shuffled[len(ato_victims) + len(card_victims) :]

        for c in normal:
            switch = None
            if c in others[:k]:
                switch = self.legit_new_device(c)
            self.everyday(c, max(self.start, c.opened_at), self.end, switch)
        for c in others[k : 2 * k]:
            self.legit_travel(c)
        for c in others[2 * k : 3 * k]:
            self.legit_large_purchase(c)
        for c in others[3 * k : 4 * k]:
            self.legit_new_beneficiary(c)
        for c in others[4 * k : 4 * k + k // 2 + 1]:
            self.legit_password_reset(c)
        for c in ato_victims:
            self.account_takeover(c, rng.choice(ato_pool), mule_payees)
        for c in card_victims:
            self.card_testing(c, rng.choice(card_pool))
        for ring in rings:
            self.ring_activity(ring)

        # APP scams and their look-alikes go last, each on established customers of its own: they
        # place a payment at an exact multiple of the customer's 90-day average, which only holds if
        # nothing is added to that customer's history afterwards. Going last also leaves every row
        # generated above exactly as it was before these scenarios existed.
        established = [c for c in others[5 * k :] if c.opened_at < self.start]
        for i, scenario in enumerate((self.app_scam, self.legit_large_new_payee, self.legit_large_known_payee)):
            for c in established[i * k : (i + 1) * k]:
                scenario(c)
        for c in [c for c in established[3 * k :] if c.segment in ("business", "affluent")][: max(1, k // 2)]:
            self.legit_business_supplier(c)

        self.watchlists(rings[0], ato_pool, card_pool)

    def write(self, db: Session) -> dict:
        txns = sorted(self.rows["transactions"], key=lambda r: r["timestamp"])
        for i, row in enumerate(txns, start=1):
            row["id"] = format_id("TX", i)
        self.rows["transactions"] = txns
        order = [
            (models.Customer, "customers"), (models.Account, "accounts"), (models.Device, "devices"),
            (models.Counterparty, "counterparties"), (models.Transaction, "transactions"),
            (models.AccountEvent, "account_events"), (models.WatchlistEntry, "watchlist_entries"),
            (models.IpReputation, "ip_reputation"),
        ]
        for model, key in order:
            rows = self.rows[key]
            for i in range(0, len(rows), 2000):
                db.execute(insert(model), rows[i : i + 2000])
        db.commit()
        return self.summary()

    def summary(self) -> dict:
        txns = self.rows["transactions"]
        scenarios: Dict[str, int] = {}
        for row in txns:
            if row["scenario"]:
                scenarios[row["scenario"]] = scenarios.get(row["scenario"], 0) + 1
        return {
            "customers": len(self.rows["customers"]),
            "transactions": len(txns),
            "events": len(self.rows["account_events"]),
            "fraud_transactions": sum(1 for row in txns if row["is_fraud"]),
            "transactions_by_scenario": scenarios,
            "history_start": self.start.isoformat(),
            "history_end": self.end.isoformat(),
        }


FRAUD_TABLES = [
    models.CaseNote, models.FraudFeedback, models.FraudCase, models.FraudAlert, models.AuditLog,
    models.FraudModelVersion, models.AccountEvent, models.Transaction, models.WatchlistEntry,
    models.IpReputation, models.Counterparty, models.Device, models.Account, models.Customer,
]


def has_data(db: Session) -> bool:
    return db.query(models.Customer.id).first() is not None


def reset(db: Session) -> None:
    """Delete all fraud-investigation data (development/demo only - this includes the audit log)."""
    for model in FRAUD_TABLES:
        db.query(model).delete()
    db.commit()


def generate(db: Session, cfg: SyntheticConfig) -> dict:
    world = SyntheticWorld(cfg)
    world.generate()
    return world.write(db)
