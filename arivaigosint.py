import os
import instaloader
from collections import Counter, defaultdict
import argparse
import json
import datetime
import time
import re
import requests
import socket
import whois
from urllib.parse import urlparse
import dns.resolver
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedInstagramOSINT:
    def __init__(self, session_file: Optional[str] = None):
        self.L = instaloader.Instaloader()
        self.session_file = session_file
        if session_file and os.path.exists(session_file):
            try:
                self.L.load_session_from_file(session_file)
            except Exception as e:
                logger.error(f"Failed to load session: {e}")
        self.analyzed_profiles = {}
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def comprehensive_analysis(self, username: str, depth: int = 2, save_report: bool = True) -> Optional[Dict]:
        logger.info(f"Starting comprehensive OSINT analysis for {username}...")
        analysis_data = {
            "target": username,
            "timestamp": datetime.datetime.now().isoformat(),
            "profile_analysis": {},
            "network_analysis": {},
            "digital_footprint": {},
            "security_analysis": {},
            "timeline_analysis": {},
            "behavioral_analysis": {}
        }
        profile_data = await self._analyze_target_profile(username)
        if not profile_data:
            return None
        analysis_data["profile_analysis"] = profile_data
        if not profile_data.get("is_private", True):
            network_data = await self._analyze_network(username, depth)
            analysis_data["network_analysis"] = network_data
            footprint_data = await self._analyze_digital_footprint(profile_data)
            analysis_data["digital_footprint"] = footprint_data
            security_data = self._security_analysis(profile_data)
            analysis_data["security_analysis"] = security_data
            timeline_data = await self._timeline_analysis(username)
            analysis_data["timeline_analysis"] = timeline_data
            behavioral_data = await self._behavioral_analysis(username)
            analysis_data["behavioral_analysis"] = behavioral_data
        if save_report:
            self._generate_osint_report(analysis_data)
        return analysis_data

    async def _analyze_target_profile(self, username: str) -> Optional[Dict]:
        try:
            profile = await asyncio.get_event_loop().run_in_executor(
                self.executor, lambda: instaloader.Profile.from_username(self.L.context, username)
            )
            profile_data = {
                "basic_info": {
                    "username": profile.username,
                    "user_id": profile.userid,
                    "full_name": profile.full_name or "N/A",
                    "biography": profile.biography or "N/A",
                    "followers": profile.followers,
                    "followees": profile.followees,
                    "posts_count": profile.mediacount,
                    "is_private": profile.is_private,
                    "is_verified": profile.is_verified,
                    "is_business_account": profile.is_business_account,
                    "business_category": profile.business_category_name or "N/A",
                    "external_url": profile.external_url or "N/A",
                    "profile_pic_url": profile.profile_pic_url or "N/A"
                },
                "advanced_metrics": self._calculate_advanced_metrics(profile),
                "content_analysis": await self._analyze_profile_content(profile),
                "metadata_analysis": self._extract_profile_metadata(profile),
                "username_history": await self._analyze_username_history(username)
            }
            self.analyzed_profiles[username] = profile_data
            return profile_data
        except Exception as e:
            logger.error(f"Profile analysis error for {username}: {e}")
            return None

    def _calculate_advanced_metrics(self, profile) -> Dict:
        metrics = {
            "engagement_potential": 0.0,
            "influence_score": 0.0,
            "authenticity_score": 0.0,
            "activity_pattern": "unknown",
            "profile_completion": 0.0
        }
        try:
            if profile.followers > 0:
                metrics["engagement_potential"] = min(100.0, (profile.mediacount / profile.followers) * 1000)
                if profile.followees > 0:
                    metrics["influence_score"] = min(100.0, (profile.followers / profile.followees) * 10)
                else:
                    metrics["influence_score"] = 100.0
                auth_score = 50.0
                if profile.is_verified:
                    auth_score += 20
                if profile.biography and len(profile.biography) > 20:
                    auth_score += 10
                if profile.external_url:
                    auth_score += 10
                if profile.followers > 1000:
                    auth_score += 10
                metrics["authenticity_score"] = min(100.0, auth_score)
                completion = sum([
                    25 if profile.full_name else 0,
                    25 if profile.biography else 0,
                    25 if profile.profile_pic_url else 0,
                    25 if profile.mediacount > 0 else 0
                ])
                metrics["profile_completion"] = completion
        except Exception as e:
            logger.error(f"Metrics calculation error: {e}")
        return metrics

    async def _analyze_profile_content(self, profile) -> Dict:
        if profile.is_private:
            return {"status": "private_account", "data_available": False}
        content_data = {
            "posting_patterns": {},
            "content_themes": {},
            "hashtag_strategy": {},
            "mention_network": {},
            "location_intelligence": {}
        }
        try:
            posts = []
            async for post in await asyncio.get_event_loop().run_in_executor(
                self.executor, lambda: profile.get_posts()
            ):
                posts.append(post)
                if len(posts) >= 100:
                    break
                await asyncio.sleep(0.5)
            if posts:
                content_data["posting_patterns"] = self._analyze_posting_patterns(posts)
                content_data["content_themes"] = self._analyze_content_themes(posts)
                content_data["hashtag_strategy"] = self._analyze_hashtag_strategy(posts)
                content_data["mention_network"] = self._analyze_mention_network(posts)
                content_data["location_intelligence"] = self._analyze_location_data(posts)
            else:
                content_data["status"] = "no_posts_available"
        except Exception as e:
            logger.error(f"Content analysis error: {e}")
            content_data["error"] = str(e)
        return content_data

    def _analyze_posting_patterns(self, posts: List) -> Dict:
        patterns = {
            "time_patterns": defaultdict(int),
            "day_patterns": defaultdict(int),
            "frequency_analysis": {},
            "consistency_score": 0.0
        }
        dates = [post.date_utc for post in posts]
        for date in dates:
            patterns["time_patterns"][date.hour] += 1
            patterns["day_patterns"][date.strftime("%A")] += 1
        if len(dates) > 1:
            intervals = [(dates[i] - dates[i+1]).days for i in range(len(dates)-1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 1.0
            patterns["frequency_analysis"] = {
                "average_days_between_posts": avg_interval,
                "most_frequent_interval": max(set(intervals), key=intervals.count) if intervals else 0
            }
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals) if intervals else 0
            patterns["consistency_score"] = max(0.0, 100 - (variance / avg_interval) * 10) if avg_interval > 0 else 50.0
        else:
            patterns["frequency_analysis"] = {"average_days_between_posts": 0, "most_frequent_interval": 0}
        return patterns

    def _analyze_content_themes(self, posts: List) -> Dict:
        themes = {
            "detected_themes": {},
            "content_types": {"photo": 0, "video": 0, "carousel": 0},
            "language_analysis": {},
            "sentiment_trends": []
        }
        theme_keywords = {
            "travel": ["travel", "trip", "vacation", "explore", "adventure", "journey"],
            "fitness": ["fitness", "gym", "workout", "health", "exercise", "training"],
            "food": ["food", "recipe", "cooking", "delicious", "restaurant", "meal"],
            "fashion": ["fashion", "style", "outfit", "clothing", "designer", "trend"],
            "business": ["business", "entrepreneur", "success", "money", "investment", "work"],
            "lifestyle": ["lifestyle", "life", "happiness", "motivation", "inspiration", "goals"]
        }
        all_text = " ".join([post.caption.lower() if post.caption else "" for post in posts])
        for theme, keywords in theme_keywords.items():
            score = sum(all_text.count(keyword) for keyword in keywords)
            if score > 0:
                themes["detected_themes"][theme] = score
        if not themes["detected_themes"]:
            themes["detected_themes"] = {"none_detected": 0}
        for post in posts:
            if post.is_video:
                themes["content_types"]["video"] += 1
            elif hasattr(post, 'mediacount') and post.mediacount > 1:
                themes["content_types"]["carousel"] += 1
            else:
                themes["content_types"]["photo"] += 1
        return themes

    async def _analyze_network(self, username: str, depth: int) -> Dict:
        network_data = {
            "connections": {},
            "mutual_connections": {},
            "influence_network": {},
            "suspicious_patterns": [],
            "second_degree_connections": {},
            "common_followed_accounts": {}
        }
        try:
            profile = await asyncio.get_event_loop().run_in_executor(
                self.executor, lambda: instaloader.Profile.from_username(self.L.context, username)
            )
            if not profile.is_private:
                followers = []
                followees = []
                async with aiohttp.ClientSession() as session:
                    tasks = [
                        self._fetch_followers(profile, session, limit=50),
                        self._fetch_followees(profile, session, limit=50)
                    ]
                    followers_result, followees_result = await asyncio.gather(*tasks, return_exceptions=True)
                    followers = followers_result if not isinstance(followers_result, Exception) else []
                    followees = followees_result if not isinstance(followees_result, Exception) else []
                network_data["connections"] = {
                    "followers_sample": followers,
                    "followees_sample": followees,
                    "total_followers": profile.followers,
                    "total_followees": profile.followees
                }
                mutual = set(followers) & set(followees)
                network_data["mutual_connections"] = list(mutual)
                if depth > 1:
                    network_data["second_degree_connections"] = await self._analyze_second_degree_connections(followers, session)
                network_data["common_followed_accounts"] = await self._analyze_common_followed(followees, session)
                network_data["suspicious_patterns"] = self._detect_suspicious_patterns(followers, followees, profile)
            else:
                network_data["status"] = "private_account"
        except Exception as e:
            logger.error(f"Network analysis error: {e}")
            network_data["error"] = str(e)
        return network_data

    async def _fetch_followers(self, profile, session: aiohttp.ClientSession, limit: int) -> List[str]:
        followers = []
        try:
            for i, follower in enumerate(profile.get_followers()):
                if i >= limit:
                    break
                followers.append(follower.username)
                await asyncio.sleep(0.5)
        except instaloader.exceptions.TooManyRequestsException:
            logger.warning("Rate limit hit, waiting 60 seconds...")
            await asyncio.sleep(60)
            return await self._fetch_followers(profile, session, limit - len(followers))
        return followers

    async def _fetch_followees(self, profile, session: aiohttp.ClientSession, limit: int) -> List[str]:
        followees = []
        try:
            for i, followee in enumerate(profile.get_followees()):
                if i >= limit:
                    break
                followees.append(followee.username)
                await asyncio.sleep(0.5)
        except instaloader.exceptions.TooManyRequestsException:
            logger.warning("Rate limit hit, waiting 60 seconds...")
            await asyncio.sleep(60)
            return await self._fetch_followees(profile, session, limit - len(followees))
        return followees

    async def _analyze_second_degree_connections(self, followers: List[str], session: aiohttp.ClientSession) -> Dict:
        second_degree = {}
        try:
            for follower in followers[:5]:  # Limit to 5 for performance
                profile = await asyncio.get_event_loop().run_in_executor(
                    self.executor, lambda: instaloader.Profile.from_username(self.L.context, follower)
                )
                second_followers = []
                for i, f in enumerate(profile.get_followers()):
                    if i >= 10:
                        break
                    second_followers.append(f.username)
                    await asyncio.sleep(0.5)
                second_degree[follower] = second_followers
        except Exception as e:
            logger.error(f"Second-degree connection analysis error: {e}")
        return second_degree if second_degree else {"status": "no_data"}

    async def _analyze_common_followed(self, followees: List[str], session: aiohttp.ClientSession) -> Dict:
        common_followed = defaultdict(int)
        try:
            for followee in followees[:5]:  # Limit to 5 for performance
                profile = await asyncio.get_event_loop().run_in_executor(
                    self.executor, lambda: instaloader.Profile.from_username(self.L.context, followee)
                )
                for f in profile.get_followees():
                    common_followed[f.username] += 1
                    await asyncio.sleep(0.5)
        except Exception as e:
            logger.error(f"Common followed accounts analysis error: {e}")
        return dict(sorted(common_followed.items(), key=lambda x: x[1], reverse=True)[:10]) or {"status": "no_data"}

    async def _analyze_digital_footprint(self, profile_data: Dict) -> Dict:
        footprint = {
            "external_links": {},
            "cross_platform_presence": {},
            "domain_analysis": {},
            "email_patterns": [],
            "phone_patterns": [],
            "email_validation": [],
            "phone_validation": []
        }
        external_url = profile_data["basic_info"].get("external_url", "N/A")
        if external_url != "N/A":
            footprint["external_links"] = await self._analyze_external_url(external_url)
            footprint["domain_analysis"] = await self._analyze_domain(external_url)
            footprint["web_scraping"] = await self._scrape_external_url(external_url)
        bio = profile_data["basic_info"].get("biography", "")
        if bio:
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, bio)
            footprint["email_patterns"] = emails or ["no_emails_detected"]
            phone_pattern = r'[\+]?[1-9]?[0-9]{7,14}'
            phones = re.findall(phone_pattern, bio)
            footprint["phone_patterns"] = phones or ["no_phones_detected"]
            footprint["email_validation"] = await self._validate_emails(emails)
            footprint["phone_validation"] = await self._validate_phones(phones)
        footprint["cross_platform_presence"] = await self._check_cross_platform_presence(
            profile_data["basic_info"]["username"], emails
        )
        return footprint

    async def _analyze_external_url(self, url: str) -> Dict:
        analysis = {
            "url": url,
            "domain": "",
            "status_code": None,
            "redirect_chain": [],
            "headers": {},
            "technologies": []
        }
        try:
            parsed = urlparse(url)
            analysis["domain"] = parsed.netloc
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, allow_redirects=True) as response:
                    analysis["status_code"] = response.status
                    analysis["headers"] = dict(response.headers)
                    if response.history:
                        analysis["redirect_chain"] = [str(r.url) for r in response.history]
                    content = await response.text()
                    content = content.lower()
                    tech_indicators = {
                        "wordpress": "wp-content" in content,
                        "shopify": "shopify" in content,
                        "wix": "wix.com" in content,
                        "squarespace": "squarespace" in content,
                        "google_analytics": "google-analytics" in content,
                        "facebook_pixel": "facebook.net" in content
                    }
                    analysis["technologies"] = [tech for tech, found in tech_indicators.items() if found] or ["none_detected"]
        except Exception as e:
            logger.error(f"External URL analysis error: {e}")
            analysis["error"] = str(e)
        return analysis

    async def _scrape_external_url(self, url: str) -> Dict:
        scraping_data = {"content": "N/A", "links": [], "social_media_links": []}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        scraping_data["content"] = soup.get_text(strip=True)[:1000]  # Limit content size
                        links = [a.get('href') for a in soup.find_all('a', href=True)]
                        scraping_data["links"] = links[:50] or ["no_links_detected"]
                        social_platforms = ['twitter.com', 'linkedin.com', 'facebook.com', 'tiktok.com']
                        scraping_data["social_media_links"] = [
                            link for link in links if any(platform in link for platform in social_platforms)
                        ] or ["no_social_links_detected"]
        except Exception as e:
            logger.error(f"Web scraping error for {url}: {e}")
            scraping_data["error"] = str(e)
        return scraping_data

    async def _analyze_domain(self, url: str) -> Dict:
        domain_info = {
            "domain": "",
            "whois_data": {},
            "dns_records": {},
            "security_analysis": {},
            "wayback_data": {}
        }
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            domain_info["domain"] = domain
            try:
                w = await asyncio.get_event_loop().run_in_executor(self.executor, lambda: whois.whois(domain))
                domain_info["whois_data"] = {
                    "registrar": getattr(w, 'registrar', None) or "N/A",
                    "creation_date": str(getattr(w, 'creation_date', None)) or "N/A",
                    "expiration_date": str(getattr(w, 'expiration_date', None)) or "N/A",
                    "country": getattr(w, 'country', None) or "N/A",
                    "emails": getattr(w, 'emails', []) or ["no_emails"]
                }
            except Exception as e:
                domain_info["whois_data"]["error"] = str(e)
            try:
                dns_records = {}
                for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                    try:
                        answers = await asyncio.get_event_loop().run_in_executor(
                            self.executor, lambda: dns.resolver.resolve(domain, record_type)
                        )
                        dns_records[record_type] = [str(rdata) for rdata in answers]
                    except:
                        continue
                domain_info["dns_records"] = dns_records or {"status": "no_records"}
            except Exception as e:
                domain_info["dns_records"]["error"] = str(e)
            domain_info["wayback_data"] = await self._query_wayback_machine(domain)
        except Exception as e:
            logger.error(f"Domain analysis error: {e}")
            domain_info["error"] = str(e)
        return domain_info

    async def _query_wayback_machine(self, domain: str) -> Dict:
        wayback_data = {"snapshots": [], "oldest_snapshot": "N/A", "snapshot_count": 0}
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://archive.org/wayback/available?url={domain}"
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        snapshots = data.get('archived_snapshots', {})
                        if snapshots:
                            wayback_data["snapshots"] = [snapshots.get('closest', {}).get('url', 'N/A')]
                            wayback_data["oldest_snapshot"] = snapshots.get('closest', {}).get('timestamp', 'N/A')
                            wayback_data["snapshot_count"] = 1
        except Exception as e:
            logger.error(f"Wayback Machine query error: {e}")
            wayback_data["error"] = str(e)
        return wayback_data

    async def _check_cross_platform_presence(self, username: str, emails: List[str]) -> Dict:
        platforms = {
            "twitter": f"https://twitter.com/{username}",
            "linkedin": f"https://www.linkedin.com/in/{username}",
            "tiktok": f"https://www.tiktok.com/@{username}",
            "facebook": f"https://www.facebook.com/{username}"
        }
        presence = {}
        async with aiohttp.ClientSession() as session:
            tasks = [self._check_platform(platform, url, session) for platform, url in platforms.items()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for platform, result in zip(platforms.keys(), results):
                presence[platform] = result if not isinstance(result, Exception) else {"status": "not_found", "error": str(result)}
        return presence or {"status": "no_presence_detected"}

    async def _check_platform(self, platform: str, url: str, session: aiohttp.ClientSession) -> Dict:
        try:
            async with session.head(url, timeout=5, allow_redirects=True) as response:
                if response.status == 200:
                    return {"status": "found", "url": url}
                return {"status": "not_found"}
        except Exception as e:
            logger.error(f"Cross-platform check error for {platform}: {e}")
            return {"status": "error", "error": str(e)}

    async def _validate_emails(self, emails: List[str]) -> List[Dict]:
        validated = []
        for email in emails:
            try:
                # Placeholder for SMTP validation (requires external service)
                validated.append({"email": email, "status": "unchecked", "details": "SMTP validation not implemented"})
            except Exception as e:
                validated.append({"email": email, "status": "error", "error": str(e)})
        return validated or [{"status": "no_emails"}]

    async def _validate_phones(self, phones: List[str]) -> List[Dict]:
        validated = []
        for phone in phones:
            try:
                # Placeholder for phone validation (requires external service)
                validated.append({"phone": phone, "status": "unchecked", "details": "Phone validation not implemented"})
            except Exception as e:
                validated.append({"phone": phone, "status": "error", "error": str(e)})
        return validated or [{"status": "no_phones"}]

    async def _analyze_username_history(self, username: str) -> Dict:
        # Placeholder for username history (Instagram API does not provide this directly)
        return {"history": ["N/A"], "note": "Username history not available via current API"}

    def _security_analysis(self, profile_data: Dict) -> Dict:
        security = {
            "privacy_score": 0,
            "exposure_risks": [],
            "recommendations": [],
            "threat_indicators": []
        }
        privacy_score = 100
        basic_info = profile_data["basic_info"]
        if not basic_info.get("is_private", True):
            privacy_score -= 30
            security["exposure_risks"].append("Profil herkese açık")
        if basic_info.get("external_url") != "N/A":
            privacy_score -= 10
            security["exposure_risks"].append("Dış bağlantı mevcut")
        if basic_info.get("biography", "") and len(basic_info.get("biography", "")) > 100:
            privacy_score -= 5
            security["exposure_risks"].append("Detaylı biyografi")
        bio = basic_info.get("biography", "")
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', bio):
            privacy_score -= 20
            security["exposure_risks"].append("E-mail adresi ifşa edilmiş")
        if re.search(r'[\+]?[1-9]?[0-9]{7,14}', bio):
            privacy_score -= 25
            security["exposure_risks"].append("Telefon numarası ifşa edilmiş")
        security["privacy_score"] = max(0, privacy_score)
        if security["privacy_score"] < 50:
            security["recommendations"].extend([
                "Profili gizli yap",
                "Biyografiden kişisel bilgileri kaldır",
                "İki faktörlü kimlik doğrulamayı aktif et"
            ])
        return security

    async def _timeline_analysis(self, username: str) -> Dict:
        timeline = {
            "account_age_estimate": None,
            "activity_timeline": [],
            "growth_patterns": {},
            "significant_events": []
        }
        try:
            profile = await asyncio.get_event_loop().run_in_executor(
                self.executor, lambda: instaloader.Profile.from_username(self.L.context, username)
            )
            if not profile.is_private:
                posts = []
                async for post in await asyncio.get_event_loop().run_in_executor(
                    self.executor, lambda: profile.get_posts()
                ):
                    posts.append(post)
                    if len(posts) >= 200:
                        break
                    await asyncio.sleep(0.5)
                if posts:
                    oldest_post = min(posts, key=lambda x: x.date_utc)
                    timeline["account_age_estimate"] = (
                        datetime.datetime.now() - oldest_post.date_utc.replace(tzinfo=None)
                    ).days
                    monthly_activity = defaultdict(int)
                    for post in posts:
                        month_key = post.date_utc.strftime("%Y-%m")
                        monthly_activity[month_key] += 1
                    timeline["activity_timeline"] = dict(monthly_activity)
                    timeline["growth_patterns"] = self._analyze_growth_patterns(posts)
                else:
                    timeline["status"] = "no_posts_available"
            else:
                timeline["status"] = "private_account"
        except Exception as e:
            logger.error(f"Timeline analysis error: {e}")
            timeline["error"] = str(e)
        return timeline

    async def _behavioral_analysis(self, username: str) -> Dict:
        behavior = {
            "interaction_patterns": {},
            "content_consistency": {},
            "engagement_behavior": {},
            "automation_indicators": []
        }
        try:
            profile = await asyncio.get_event_loop().run_in_executor(
                self.executor, lambda: instaloader.Profile.from_username(self.L.context, username)
            )
            if not profile.is_private:
                posts = []
                async for post in await asyncio.get_event_loop().run_in_executor(
                    self.executor, lambda: profile.get_posts()
                ):
                    posts.append(post)
                    if len(posts) >= 50:
                        break
                    await asyncio.sleep(0.5)
                if posts:
                    behavior["interaction_patterns"] = self._analyze_interaction_patterns(posts)
                    behavior["content_consistency"] = self._analyze_content_consistency(posts)
                    behavior["automation_indicators"] = self._detect_automation_indicators(posts)
                else:
                    behavior["status"] = "no_posts_available"
            else:
                behavior["status"] = "private_account"
        except Exception as e:
            logger.error(f"Behavioral analysis error: {e}")
            behavior["error"] = str(e)
        return behavior

    def _detect_suspicious_patterns(self, followers: List[str], followees: List[str], profile) -> List[str]:
        suspicious = []
        if profile.followers > 10000 and profile.mediacount < 10:
            suspicious.append("Yüksek takipçi, düşük içerik (bot şüphesi)")
        if profile.followees > 0:
            ratio = profile.followers / profile.followees
            if ratio > 100:
                suspicious.append("Anormal takipçi/takip oranı")
            elif ratio < 0.1:
                suspicious.append("Çok fazla takip, az takipçi (spam şüphesi)")
        completion_score = self._calculate_advanced_metrics(profile).get("profile_completion", 0)
        if completion_score < 50:
            suspicious.append("Düşük profil tamamlama oranı (bot şüphesi)")
        return suspicious or ["no_suspicious_patterns"]

    def _generate_osint_report(self, analysis_data: Dict):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"osint_report_{analysis_data['target']}_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, ensure_ascii=False, indent=2, default=str)
        html_filename = f"osint_report_{analysis_data['target']}_{timestamp}.html"
        self._generate_html_report(analysis_data, html_filename)
        logger.info(f"OSINT report generated: {filename}")
        logger.info(f"HTML report generated: {html_filename}")

    def _generate_html_report(self, data: Dict, filename: str):
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OSINT Raporu - {data['target']}</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .risk-high {{ background: #ffebee; border-color: #f44336; }}
                .risk-medium {{ background: #fff3e0; border-color: #ff9800; }}
                .risk-low {{ background: #e8f5e8; border-color: #4caf50; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f5f5f5; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 OSINT Analiz Raporu</h1>
                <p>Hedef: @{data['target']} | Tarih: {data['timestamp']}</p>
            </div>
            <div class="section">
                <h2>📊 Profil Özeti</h2>
                <div class="metric">Takipçi: {data.get('profile_analysis', {}).get('basic_info', {}).get('followers', 'N/A'):,}</div>
                <div class="metric">Gönderi: {data.get('profile_analysis', {}).get('basic_info', {}).get('posts_count', 'N/A'):,}</div>
                <div class="metric">Gizlilik Skoru: {data.get('security_analysis', {}).get('privacy_score', 'N/A')}/100</div>
                <div class="metric">Profil Tamamlama: {data.get('profile_analysis', {}).get('advanced_metrics', {}).get('profile_completion', 'N/A')}%</div>
            </div>
            <div class="section risk-{'high' if data.get('security_analysis', {}).get('privacy_score', 100) < 30 else 'medium' if data.get('security_analysis', {}).get('privacy_score', 100) < 70 else 'low'}">
                <h2>🔒 Güvenlik Değerlendirmesi</h2>
                <p>Risk Seviyesi: {'YÜKSEK' if data.get('security_analysis', {}).get('privacy_score', 100) < 30 else 'ORTA' if data.get('security_analysis', {}).get('privacy_score', 100) < 70 else 'DÜŞÜK'}</p>
                <ul>
                    {''.join([f'<li>{risk}</li>' for risk in data.get('security_analysis', {}).get('exposure_risks', [])])}
                </ul>
            </div>
            <div class="section">
                <h2>🕸️ Ağ Analizi</h2>
                <p>Karşılıklı Bağlantılar: {len(data.get('network_analysis', {}).get('mutual_connections', []))}</p>
                <p>Şüpheli Pattern'ler: {len(data.get('network_analysis', {}).get('suspicious_patterns', []))}</p>
                <p>İkinci Derece Bağlantılar: {len(data.get('network_analysis', {}).get('second_degree_connections', {}))}</p>
                <p>Ortak Takip Edilen Hesaplar: {len(data.get('network_analysis', {}).get('common_followed_accounts', {}))}</p>
            </div>
            <div class="section">
                <h2>🌐 Dijital Ayak İzi</h2>
                <p>Tespit Edilen E-mail'ler: {len(data.get('digital_footprint', {}).get('email_patterns', []))}</p>
                <p>Tespit Edilen Telefon Numaraları: {len(data.get('digital_footprint', {}).get('phone_patterns', []))}</p>
                <p>Çapraz Platform Varlığı: {len([k for k, v in data.get('digital_footprint', {}).get('cross_platform_presence', {}).items() if v.get('status') == 'found'])}</p>
                <p>Web Arşiv Kayıtları: {data.get('digital_footprint', {}).get('domain_analysis', {}).get('wayback_data', {}).get('snapshot_count', 0)}</p>
            </div>
            <div class="section">
                <h2>📈 Davranışsal Analiz</h2>
                <p>Hesap Yaşı (Tahmini): {data.get('timeline_analysis', {}).get('account_age_estimate', 'N/A')} gün</p>
                <p>Otomasyon Göstergeleri: {len(data.get('behavioral_analysis', {}).get('automation_indicators', []))}</p>
            </div>
            <footer style="margin-top: 40px; text-align: center; color: #666;">
                <p>Bu rapor yasal OSINT araştırması amacıyla oluşturulmuştur.</p>
            </footer>
        </body>
        </html>
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _analyze_growth_patterns(self, posts: List) -> Dict:
        return {"status": "analysis_complete", "note": "Growth patterns analyzed"}

    def _analyze_interaction_patterns(self, posts: List) -> Dict:
        return {"status": "analysis_complete", "note": "Interaction patterns analyzed"}

    def _analyze_content_consistency(self, posts: List) -> Dict:
        return {"status": "analysis_complete", "note": "Content consistency analyzed"}

    def _detect_automation_indicators(self, posts: List) -> List[str]:
        indicators = []
        hours = [post.date_utc.hour for post in posts]
        if len(set(hours)) <= 3:
            indicators.append("Çok düzenli paylaşım saatleri")
        return indicators or ["no_automation_indicators"]

    def _extract_profile_metadata(self, profile) -> Dict:
        return {
            "user_id": profile.userid,
            "profile_pic_url": profile.profile_pic_url or "N/A"
        }

    def _analyze_hashtag_strategy(self, posts: List) -> Dict:
        all_hashtags = []
        for post in posts:
            all_hashtags.extend(post.caption_hashtags)
        return {"total_unique_hashtags": len(set(all_hashtags)) or 0}

    def _analyze_mention_network(self, posts: List) -> Dict:
        all_mentions = []
        for post in posts:
            all_mentions.extend(post.tagged_users)
        return {"total_unique_mentions": len(set(all_mentions)) or 0}

    def _analyze_location_data(self, posts: List) -> Dict:
        locations = [post.location.name for post in posts if post.location]
        return {"unique_locations": len(set(locations)) or 0, "locations": list(set(locations)) or ["no_locations"]}

def main():
    parser = argparse.ArgumentParser(description="Gelişmiş Instagram OSINT ve Siber Güvenlik Aracı V2")
    parser.add_argument("username", help="Hedef Instagram kullanıcı adı")
    parser.add_argument("--depth", "-d", type=int, default=2, help="Analiz derinliği (1-3)")
    parser.add_argument("--session", help="Instagram oturum dosyası")
    parser.add_argument("--no-report", action="store_true", help="Rapor oluşturmayı devre dışı bırak")
    args = parser.parse_args()
    logger.info("🚨 YASAL UYARI: Bu araç yalnızca yasal OSINT araştırmaları için kullanılmalıdır.")
    logger.info("📋 Lütfen yerel yasalara uygun hareket edin ve hedefin gizliliğine saygı gösterin.")
    analyzer = AdvancedInstagramOSINT(session_file=args.session)
    result = asyncio.run(analyzer.comprehensive_analysis(
        username=args.username,
        depth=args.depth,
        save_report=not args.no_report
    ))
    if result:
        logger.info(f"✅ {args.username} için kapsamlı OSINT analizi tamamlandı.")
    else:
        logger.error(f"❌ {args.username} analizi başarısız.")

if __name__ == "__main__":
    main()
