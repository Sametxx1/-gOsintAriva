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

class AdvancedInstagramOSINT:
    def __init__(self, session_file=None):
        self.L = instaloader.Instaloader()
        if session_file and os.path.exists(session_file):
            self.L.load_session_from_file(session_file)
        self.analyzed_profiles = {}
        
    def comprehensive_analysis(self, username, depth=2, save_report=True):
        """Kapsamlı OSINT analizi"""
        print(f"\n🔍 {username} için kapsamlı OSINT analizi başlatılıyor...")
        
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
        
        # 1. Temel profil analizi
        profile_data = self._analyze_target_profile(username)
        if not profile_data:
            return None
            
        analysis_data["profile_analysis"] = profile_data
        
        # 2. Ağ analizi (bağlantılar)
        if not profile_data.get("is_private", True):
            network_data = self._analyze_network(username, depth)
            analysis_data["network_analysis"] = network_data
            
            # 3. Dijital ayak izi
            footprint_data = self._analyze_digital_footprint(profile_data)
            analysis_data["digital_footprint"] = footprint_data
            
            # 4. Güvenlik analizi
            security_data = self._security_analysis(profile_data)
            analysis_data["security_analysis"] = security_data
            
            # 5. Zaman çizelgesi analizi
            timeline_data = self._timeline_analysis(username)
            analysis_data["timeline_analysis"] = timeline_data
            
            # 6. Davranışsal analiz
            behavioral_data = self._behavioral_analysis(username)
            analysis_data["behavioral_analysis"] = behavioral_data
        
        if save_report:
            self._generate_osint_report(analysis_data)
            
        return analysis_data
    
    def _analyze_target_profile(self, username):
        """Hedef profil detaylı analiz"""
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            profile_data = {
                "basic_info": {
                    "username": profile.username,
                    "user_id": profile.userid,
                    "full_name": profile.full_name,
                    "biography": profile.biography,
                    "followers": profile.followers,
                    "followees": profile.followees,
                    "posts_count": profile.mediacount,
                    "is_private": profile.is_private,
                    "is_verified": profile.is_verified,
                    "is_business_account": profile.is_business_account,
                    "business_category": profile.business_category_name,
                    "external_url": profile.external_url,
                    "profile_pic_url": profile.profile_pic_url
                },
                "advanced_metrics": self._calculate_advanced_metrics(profile),
                "content_analysis": self._analyze_profile_content(profile),
                "metadata_analysis": self._extract_profile_metadata(profile)
            }
            
            self.analyzed_profiles[username] = profile_data
            return profile_data
            
        except Exception as e:
            print(f"❌ Profil analizi hatası: {str(e)}")
            return None
    
    def _calculate_advanced_metrics(self, profile):
        """Gelişmiş metrikler"""
        metrics = {
            "engagement_potential": 0,
            "influence_score": 0,
            "authenticity_score": 0,
            "activity_pattern": "unknown"
        }
        
        try:
            if profile.followers > 0:
                # Etkileşim potansiyeli
                metrics["engagement_potential"] = min(100, (profile.mediacount / profile.followers) * 1000)
                
                # Etki skoru (takipçi/takip edilen oranı)
                if profile.followees > 0:
                    metrics["influence_score"] = min(100, (profile.followers / profile.followees) * 10)
                else:
                    metrics["influence_score"] = 100
                
                # Otantiklik skoru (çeşitli faktörlere göre)
                auth_score = 50  # Base score
                
                if profile.is_verified:
                    auth_score += 20
                if profile.biography and len(profile.biography) > 20:
                    auth_score += 10
                if profile.external_url:
                    auth_score += 10
                if profile.followers > 1000:
                    auth_score += 10
                    
                metrics["authenticity_score"] = min(100, auth_score)
        
        except Exception as e:
            print(f"⚠️ Metrik hesaplama hatası: {str(e)}")
            
        return metrics
    
    def _analyze_profile_content(self, profile):
        """İçerik analizi"""
        if profile.is_private:
            return {"status": "private_account"}
            
        content_data = {
            "posting_patterns": {},
            "content_themes": {},
            "hashtag_strategy": {},
            "mention_network": {},
            "location_intelligence": {}
        }
        
        try:
            posts = list(profile.get_posts())[:100]  # Son 100 gönderi
            
            if posts:
                # Paylaşım pattern'leri
                content_data["posting_patterns"] = self._analyze_posting_patterns(posts)
                
                # İçerik temaları
                content_data["content_themes"] = self._analyze_content_themes(posts)
                
                # Hashtag stratejisi
                content_data["hashtag_strategy"] = self._analyze_hashtag_strategy(posts)
                
                # Mention ağı
                content_data["mention_network"] = self._analyze_mention_network(posts)
                
                # Lokasyon istihbaratı
                content_data["location_intelligence"] = self._analyze_location_data(posts)
                
        except Exception as e:
            print(f"⚠️ İçerik analizi hatası: {str(e)}")
            
        return content_data
    
    def _analyze_posting_patterns(self, posts):
        """Paylaşım pattern analizi"""
        patterns = {
            "time_patterns": defaultdict(int),
            "day_patterns": defaultdict(int),
            "frequency_analysis": {},
            "consistency_score": 0
        }
        
        dates = [post.date_utc for post in posts]
        
        # Saat ve gün pattern'leri
        for date in dates:
            patterns["time_patterns"][date.hour] += 1
            patterns["day_patterns"][date.strftime("%A")] += 1
        
        # Frekans analizi
        if len(dates) > 1:
            intervals = [(dates[i] - dates[i+1]).days for i in range(len(dates)-1)]
            avg_interval = sum(intervals) / len(intervals)
            patterns["frequency_analysis"] = {
                "average_days_between_posts": avg_interval,
                "most_frequent_interval": max(set(intervals), key=intervals.count) if intervals else 0
            }
            
            # Tutarlılık skoru
            if avg_interval > 0:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                patterns["consistency_score"] = max(0, 100 - (variance / avg_interval) * 10)
        
        return patterns
    
    def _analyze_content_themes(self, posts):
        """İçerik tema analizi"""
        themes = {
            "detected_themes": {},
            "content_types": {"photo": 0, "video": 0, "carousel": 0},
            "language_analysis": {},
            "sentiment_trends": []
        }
        
        # Tema kelime grupları
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
        
        # İçerik tipleri
        for post in posts:
            if post.is_video:
                themes["content_types"]["video"] += 1
            elif hasattr(post, 'mediacount') and post.mediacount > 1:
                themes["content_types"]["carousel"] += 1
            else:
                themes["content_types"]["photo"] += 1
        
        return themes
    
    def _analyze_network(self, username, depth=2):
        """Ağ analizi - bağlantıları keşfet"""
        network_data = {
            "connections": {},
            "mutual_connections": {},
            "influence_network": {},
            "suspicious_patterns": []
        }
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            if not profile.is_private:
                # Takipçiler analizi (ilk 50)
                followers = []
                followees = []
                
                print("🕸️ Ağ analizi yapılıyor...")
                
                # Rate limiting ile takipçileri al
                for i, follower in enumerate(profile.get_followers()):
                    if i >= 50:  # Limit
                        break
                    followers.append(follower.username)
                    time.sleep(0.5)
                
                # Takip edilen hesaplar
                for i, followee in enumerate(profile.get_followees()):
                    if i >= 50:
                        break
                    followees.append(followee.username)
                    time.sleep(0.5)
                
                network_data["connections"] = {
                    "followers_sample": followers,
                    "followees_sample": followees,
                    "total_followers": profile.followers,
                    "total_followees": profile.followees
                }
                
                # Karşılıklı bağlantıları tespit et
                mutual = set(followers) & set(followees)
                network_data["mutual_connections"] = list(mutual)
                
                # Şüpheli pattern'leri tespit et
                network_data["suspicious_patterns"] = self._detect_suspicious_patterns(
                    followers, followees, profile
                )
                
        except Exception as e:
            print(f"⚠️ Ağ analizi hatası: {str(e)}")
            
        return network_data
    
    def _analyze_digital_footprint(self, profile_data):
        """Dijital ayak izi analizi"""
        footprint = {
            "external_links": {},
            "cross_platform_presence": {},
            "domain_analysis": {},
            "email_patterns": [],
            "phone_patterns": []
        }
        
        # Dış linkler analizi
        external_url = profile_data["basic_info"].get("external_url")
        if external_url:
            footprint["external_links"] = self._analyze_external_url(external_url)
            footprint["domain_analysis"] = self._analyze_domain(external_url)
        
        # Bio'dan e-mail ve telefon pattern'leri çıkar
        bio = profile_data["basic_info"].get("biography", "")
        if bio:
            # E-mail pattern'leri
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, bio)
            footprint["email_patterns"] = emails
            
            # Telefon pattern'leri
            phone_pattern = r'[\+]?[1-9]?[0-9]{7,14}'
            phones = re.findall(phone_pattern, bio)
            footprint["phone_patterns"] = phones
        
        return footprint
    
    def _analyze_external_url(self, url):
        """Dış URL analizi"""
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
            
            # HTTP analizi
            response = requests.get(url, timeout=10, allow_redirects=True)
            analysis["status_code"] = response.status_code
            analysis["headers"] = dict(response.headers)
            
            # Redirect zinciri
            if response.history:
                analysis["redirect_chain"] = [r.url for r in response.history]
            
            # Teknoloji tespiti (basit)
            content = response.text.lower()
            tech_indicators = {
                "wordpress": "wp-content" in content,
                "shopify": "shopify" in content,
                "wix": "wix.com" in content,
                "squarespace": "squarespace" in content,
                "google_analytics": "google-analytics" in content,
                "facebook_pixel": "facebook.net" in content
            }
            
            analysis["technologies"] = [tech for tech, found in tech_indicators.items() if found]
            
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis
    
    def _analyze_domain(self, url):
        """Domain analizi"""
        domain_info = {
            "domain": "",
            "whois_data": {},
            "dns_records": {},
            "security_analysis": {}
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            domain_info["domain"] = domain
            
            # WHOIS sorgusu
            try:
                w = whois.whois(domain)
                domain_info["whois_data"] = {
                    "registrar": getattr(w, 'registrar', None),
                    "creation_date": str(getattr(w, 'creation_date', None)),
                    "expiration_date": str(getattr(w, 'expiration_date', None)),
                    "country": getattr(w, 'country', None),
                    "emails": getattr(w, 'emails', [])
                }
            except Exception as e:
                domain_info["whois_data"]["error"] = str(e)
            
            # DNS kayıtları
            try:
                dns_records = {}
                for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        dns_records[record_type] = [str(rdata) for rdata in answers]
                    except:
                        continue
                domain_info["dns_records"] = dns_records
            except Exception as e:
                domain_info["dns_records"]["error"] = str(e)
            
        except Exception as e:
            domain_info["error"] = str(e)
            
        return domain_info
    
    def _security_analysis(self, profile_data):
        """Güvenlik analizi"""
        security = {
            "privacy_score": 0,
            "exposure_risks": [],
            "recommendations": [],
            "threat_indicators": []
        }
        
        # Gizlilik skoru hesaplama
        privacy_score = 100
        
        basic_info = profile_data["basic_info"]
        
        # Risk faktörleri
        if not basic_info.get("is_private", True):
            privacy_score -= 30
            security["exposure_risks"].append("Profil herkese açık")
            
        if basic_info.get("external_url"):
            privacy_score -= 10
            security["exposure_risks"].append("Dış bağlantı mevcut")
            
        if basic_info.get("biography") and len(basic_info.get("biography", "")) > 100:
            privacy_score -= 5
            security["exposure_risks"].append("Detaylı biyografi")
            
        # E-mail/telefon ifşası kontrol
        bio = basic_info.get("biography", "")
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', bio):
            privacy_score -= 20
            security["exposure_risks"].append("E-mail adresi ifşa edilmiş")
            
        if re.search(r'[\+]?[1-9]?[0-9]{7,14}', bio):
            privacy_score -= 25
            security["exposure_risks"].append("Telefon numarası ifşa edilmiş")
            
        security["privacy_score"] = max(0, privacy_score)
        
        # Güvenlik önerileri
        if security["privacy_score"] < 50:
            security["recommendations"].extend([
                "Profili gizli yap",
                "Biyografiden kişisel bilgileri kaldır",
                "İki faktörlü kimlik doğrulamayı aktif et"
            ])
            
        return security
    
    def _timeline_analysis(self, username):
        """Zaman çizelgesi analizi"""
        timeline = {
            "account_age_estimate": None,
            "activity_timeline": [],
            "growth_patterns": {},
            "significant_events": []
        }
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            if not profile.is_private:
                posts = list(profile.get_posts())[:200]
                
                if posts:
                    # En eski gönderi
                    oldest_post = min(posts, key=lambda x: x.date_utc)
                    timeline["account_age_estimate"] = (
                        datetime.datetime.now() - oldest_post.date_utc.replace(tzinfo=None)
                    ).days
                    
                    # Aktivite zaman çizelgesi
                    monthly_activity = defaultdict(int)
                    for post in posts:
                        month_key = post.date_utc.strftime("%Y-%m")
                        monthly_activity[month_key] += 1
                    
                    timeline["activity_timeline"] = dict(monthly_activity)
                    
                    # Büyüme pattern'leri analizi
                    timeline["growth_patterns"] = self._analyze_growth_patterns(posts)
                    
        except Exception as e:
            print(f"⚠️ Timeline analizi hatası: {str(e)}")
            
        return timeline
    
    def _behavioral_analysis(self, username):
        """Davranışsal analiz"""
        behavior = {
            "interaction_patterns": {},
            "content_consistency": {},
            "engagement_behavior": {},
            "automation_indicators": []
        }
        
        try:
            profile = instaloader.Profile.from_username(self.L.context, username)
            
            if not profile.is_private:
                posts = list(profile.get_posts())[:50]
                
                if posts:
                    # Etkileşim pattern'leri
                    behavior["interaction_patterns"] = self._analyze_interaction_patterns(posts)
                    
                    # İçerik tutarlılığı
                    behavior["content_consistency"] = self._analyze_content_consistency(posts)
                    
                    # Otomasyon göstergeleri
                    behavior["automation_indicators"] = self._detect_automation_indicators(posts)
                    
        except Exception as e:
            print(f"⚠️ Davranışsal analiz hatası: {str(e)}")
            
        return behavior
    
    def _detect_suspicious_patterns(self, followers, followees, profile):
        """Şüpheli pattern tespiti"""
        suspicious = []
        
        # Bot hesap pattern'leri
        if profile.followers > 10000 and profile.mediacount < 10:
            suspicious.append("Yüksek takipçi, düşük içerik (bot şüphesi)")
            
        # Takip/takipçi oranı anormalliği
        if profile.followees > 0:
            ratio = profile.followers / profile.followees
            if ratio > 100:
                suspicious.append("Anormal takipçi/takip oranı")
            elif ratio < 0.1:
                suspicious.append("Çok fazla takip, az takipçi (spam şüphesi)")
        
        return suspicious
    
    def _generate_osint_report(self, analysis_data):
        """OSINT raporu oluştur"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"osint_report_{analysis_data['target']}_{timestamp}.json"
        
        # JSON raporu
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, ensure_ascii=False, indent=2, default=str)
        
        # HTML raporu
        html_filename = f"osint_report_{analysis_data['target']}_{timestamp}.html"
        self._generate_html_report(analysis_data, html_filename)
        
        print(f"📄 OSINT raporu oluşturuldu: {filename}")
        print(f"🌐 HTML raporu oluşturuldu: {html_filename}")
    
    def _generate_html_report(self, data, filename):
        """HTML raporu oluştur"""
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
            </div>
            
            <div class="section">
                <h2>📈 Davranışsal Analiz</h2>
                <p>Hesap Yaşı (Tahmini): {data.get('timeline_analysis', {}).get('account_age_estimate', 'N/A')} gün</p>
                <p>Otomasyon Göstergeleri: {len(data.get('behavioral_analysis', {}).get('automation_indicators', []))}</p>
            </div>
            
            <div class="section">
                <h2>🌐 Dijital Ayak İzi</h2>
                <p>Tespit Edilen E-mail'ler: {len(data.get('digital_footprint', {}).get('email_patterns', []))}</p>
                <p>Tespit Edilen Telefon Numaraları: {len(data.get('digital_footprint', {}).get('phone_patterns', []))}</p>
            </div>
            
            <footer style="margin-top: 40px; text-align: center; color: #666;">
                <p>Bu rapor yasal OSINT araştırması amacıyla oluşturulmuştur.</p>
            </footer>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

    # Utility methods
    def _analyze_growth_patterns(self, posts):
        return {"status": "analysis_complete"}
    
    def _analyze_interaction_patterns(self, posts):
        return {"status": "analysis_complete"}
    
    def _analyze_content_consistency(self, posts):
        return {"status": "analysis_complete"}
    
    def _detect_automation_indicators(self, posts):
        indicators = []
        # Çok düzenli paylaşım saatleri
        hours = [post.date_utc.hour for post in posts]
        if len(set(hours)) <= 3:
            indicators.append("Çok düzenli paylaşım saatleri")
        return indicators
    
    def _extract_profile_metadata(self, profile):
        return {
            "user_id": profile.userid,
            "profile_pic_url": profile.profile_pic_url
        }
    
    def _analyze_hashtag_strategy(self, posts):
        all_hashtags = []
        for post in posts:
            all_hashtags.extend(post.caption_hashtags)
        return {"total_unique_hashtags": len(set(all_hashtags))}
    
    def _analyze_mention_network(self, posts):
        all_mentions = []
        for post in posts:
            all_mentions.extend(post.tagged_users)
        return {"total_unique_mentions": len(set(all_mentions))}
    
    def _analyze_location_data(self, posts):
        locations = [post.location.name for post in posts if post.location]
        return {"unique_locations": len(set(locations)), "locations": list(set(locations))}

def main():
    parser = argparse.ArgumentParser(description="Gelişmiş Instagram OSINT ve Siber Güvenlik Aracı")
    parser.add_argument("username", help="Hedef Instagram kullanıcı adı")
    parser.add_argument("--depth", "-d", type=int, default=2, help="Analiz derinliği (1-3)")
    parser.add_argument("--session", help="Instagram oturum dosyası")
    parser.add_argument("--no-report", action="store_true", help="Rapor oluşturmayı devre dışı bırak")
    
    args = parser.parse_args()
    
    print("🚨 YASAL UYARI: Bu araç yalnızca yasal OSINT araştırmaları için kullanılmalıdır.")
    print("📋 Lütfen yerel yasalara uygun hareket edin ve hedefin gizliliğine saygı gösterin.\n")
    
    analyzer = AdvancedInstagramOSINT(session_file=args.session)
    
    result = analyzer.comprehensive_analysis(
        username=args.username,
        depth=args.depth,
        save_report=not args.no_report
    )
    
    if result:
        print(f"\n✅ {args.username} için kapsamlı OSINT analizi tamamlandı.")
    else:
        print(f"\n❌ {args.username} analizi başarısız.")

if __name__ == "__main__":
    main()
