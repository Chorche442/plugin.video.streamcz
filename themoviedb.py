import requests
import xbmc
import xbmcgui
import re
import io
import os
import json

FOLDER_NAME = "series_db_tmdb"

class TMDB:
    def __init__(self, addon, profile):
        self.addon = addon
        self.profile = profile
        # Použijeme API Key (v3) z nastavení
        self.API_KEY = addon.getSetting('tmdb_token')
        self.LANG    = addon.getSetting('tmdb_lang') or 'en-US'
        self.series_db_path = os.path.join(profile, FOLDER_NAME)
        self.ensure_db_exists()

    def ensure_db_exists(self):
        """Ensure that the series database directory exists"""
        try:
            if not os.path.exists(self.profile):
                os.makedirs(self.profile)
            if not os.path.exists(self.series_db_path):
                os.makedirs(self.series_db_path)
        except Exception as e:
            xbmc.log(f'WebshareCinema: Error creating directories: {str(e)}', level=xbmc.LOGERROR)

    def FindSeries(self, series_name):
        results = self.get_series_info(series_name)
        selected = self.choose_series_from_results(results)
        if selected:
            return selected
        return None

    def get_series_info(self, series_name):
        url = "https://api.themoviedb.org/3/search/tv"
        params = {
            "api_key": self.API_KEY,
            "query": series_name,
            "language": self.LANG,
            "include_adult": False
        }
        response = requests.get(url, params=params, timeout=10)
        if response.status_code != 200:
            xbmc.log(f"TMDB get_series_info error {response.status_code}", xbmc.LOGERROR)
            return []
        data = response.json()
        return data.get("results", [])

    def get_series_details(self, series_id):
        """Získá detailní info o seriálu včetně seznamu sezón."""
        url = f"https://api.themoviedb.org/3/tv/{series_id}"
        params = {"api_key": self.API_KEY, "language": self.LANG}
        response = requests.get(url, params=params, timeout=10)
        if response.status_code != 200:
            xbmc.log(f"TMDB get_series_details error {response.status_code}", xbmc.LOGERROR)
            return []
        data = response.json()
        return data.get("seasons", [])

    def get_season_episodes(self, series_id, season_number):
        """Získá seznam epizod pro danou sezónu."""
        url = f"https://api.themoviedb.org/3/tv/{series_id}/season/{season_number}"
        params = {"api_key": self.API_KEY, "language": self.LANG}
        response = requests.get(url, params=params, timeout=10)
        if response.status_code != 200:
            xbmc.log(f"TMDB get_season_episodes error {response.status_code}", xbmc.LOGERROR)
            return []
        data = response.json()
        return data.get('episodes', [])

    def search_movie(self, title):
        """Vyhledá film podle názvu a vrátí seznam výsledků."""
        url = "https://api.themoviedb.org/3/search/movie"
        params = {
            "api_key": self.API_KEY,
            "query": title,
            "language": self.LANG,
            "include_adult": False
        }
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            xbmc.log(f"TMDB search_movie error {resp.status_code}", xbmc.LOGERROR)
            return []
        return resp.json().get("results", [])

    def get_poster_url(self, file_path, size="w300"):
        """Vrátí URL plakátu."""
        if not file_path:
            return None
        return f"https://image.tmdb.org/t/p/{size}{file_path}"

    def choose_series_from_results(self, results):
        if not results:
            xbmcgui.Dialog().notification("TMDb", "Nebyly nalezeny žádné výsledky", xbmcgui.NOTIFICATION_ERROR)
            return None
        options = []
        for item in results:
            year = item.get('first_air_date', '')[:4] if item.get('first_air_date') else ''
            title = item.get('name', 'Unknown')
            display_name = f"{title} ({year})" if year else title
            options.append(display_name)
        dialog = xbmcgui.Dialog()
        idx = dialog.select("Vyber správnou variantu", options)
        if idx == -1:
            return None
        return results[idx]

    def build_tmdb_series_structure(self, selected, seasons):
        series_data = {
            "name": selected.get("name", "Unknown"),
            "original_name": selected.get("original_name", "Unknown"),
            "id": selected["id"],
            "seasons": {}
        }
        for season in seasons:
            season_number = season.get("season_number")
            if season_number == 0:
                continue
            episodes = self.get_season_episodes(selected["id"], season_number)
            if not episodes:
                continue
            season_dict = {}
            for ep in episodes:
                ep_name = ep.get("name", f"Epizoda {ep.get('episode_number')}")
                season_dict[ep_name] = {}
            series_data[season.get("name", f"Sezóna {season_number}")] = season_dict
        return series_data


def save_series_structure(series_data, folder_path):
    safe_name = re.sub(r'[^\w\-\_\. ]', '_', series_data["original_name"]).lower().replace(" ", "_")
    file_path = os.path.join(folder_path, f"{safe_name}.json")
    try:
        with io.open(file_path, 'w', encoding='utf8') as file:
            data = json.dumps(series_data, indent=2)
            file.write(data)
    except Exception as e:
        xbmc.log(f'WebshareCinema: Error saving series data: {str(e)}', level=xbmc.LOGERROR)
 def search_movie(self, movie_title):
        """Search TMDb for a movie by title."""
        url = "https://api.themoviedb.org/3/search/movie"
        params = {
            "api_key": self.API_TOKEN,
            "query": movie_title,
            "language": self.LANG,
            "include_adult": "false"
        }
        r = requests.get(url, params=params, timeout=10)
        if r.status_code != 200:
            xbmc.log(f"TMDb movie search error {r.status_code}", xbmc.LOGERROR)
            return []
        return r.json().get("results", [])

    def get_poster_url(self, poster_path, size="w500"):
        """Build full image URL from TMDb poster path."""
        if not poster_path:
            return None
        return f"https://image.tmdb.org/t/p/{size}{poster_path}"
