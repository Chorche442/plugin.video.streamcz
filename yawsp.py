# -*- coding: utf-8 -*-
import hashlib
# Module: default
# Author: cache-sk
# Created on: 10.5.2020
# License: AGPL v.3 https://www.gnu.org/licenses/agpl-3.0.html
# === FÁZE 1.1: CLEAN & TOKENIZE DOTAZU ===

import io
import os
import sys
import xbmc
import xbmcgui
import xbmcplugin
import xbmcaddon
import xbmcvfs
import requests
from xml.etree import ElementTree as ET
import hashlib
import traceback
import json
import unidecode
import re
import zipfile
import uuid
import series_manager
from themoviedb import TMDB
import webbrowser

# Fallback md5crypt implementation if not available
try:
    from md5crypt import md5crypt
except ImportError:
    def md5crypt(password, salt):
        return hashlib.md5((password + salt).encode('utf-8')).hexdigest()

STOP_WORDS = {
    'a', 'an', 'the', 'na', 'do', 'se', 'i', 'to', 'je', 's', 'že', 'co'
}

def trakt_authorize():
    client_id = _addon.getSetting('trakt_client_id')
    redirect = 'urn:ietf:wg:oauth:2.0:oob'
    url = f'https://trakt.tv/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect}'
    webbrowser.open(url)
    code = ask(None)  # Kodi dialog asking for code
    return code

def trakt_get_token(code):
    client_id = _addon.getSetting('trakt_client_id')
    client_secret = _addon.getSetting('trakt_client_secret')
    data = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
        'grant_type': 'authorization_code'
    }
    r = requests.post('https://api.trakt.tv/oauth/token', json=data, timeout=10)
    r.raise_for_status()
    token = r.json().get('access_token')
    if token:
        _addon.setSetting('trakt_oauth_token', token)
        popinfo("Trakt", "Autorizace úspěšná", icon=xbmcgui.NOTIFICATION_INFO)
    else:
        popinfo("Trakt", "Chyba při autorizaci", icon=xbmcgui.NOTIFICATION_ERROR)

def clean_and_tokenize(query: str) -> list:
    """
    Odstraní diakritiku, udělá lowercase, odstraní interpunkci a stop-slova,
    vrátí seznam čistých tokenů.
    """
    q = query.lower()
    q = unidecode.unidecode(q)
    q = re.sub(r'[^a-z0-9\s]', ' ', q)
    return [t for t in q.split() if t not in STOP_WORDS and len(t) > 1]

try:
    from urllib.parse import urlencode, parse_qsl, urlparse
except ImportError:
    from urllib import urlencode
    from urlparse import parse_qsl, urlparse

try:
    from xbmcvfs import translatePath
except ImportError:
    from xbmc import translatePath

BASE = 'https://webshare.cz'
API = BASE + '/api/'
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
HEADERS = {'User-Agent': UA, 'Referer': BASE}
REALM = ':Webshare:'
CATEGORIES = ['', 'video', 'images', 'audio', 'archives', 'docs', 'adult']
SORTS = ['', 'recent', 'rating', 'largest', 'smallest']
SEARCH_HISTORY = 'search_history'
NONE_WHAT = '%#NONE#%'
BACKUP_DB = 'D1iIcURxlR'  # Consider making this configurable

_url = sys.argv[0]
_handle = int(sys.argv[1])
_addon = xbmcaddon.Addon()
_session = requests.Session()
_session.headers.update(HEADERS)

_profile = translatePath(_addon.getAddonInfo('profile'))
if isinstance(_profile, bytes):
    _profile = _profile.decode('utf-8')

# TMDB client
tmdb = TMDB(_addon, _profile)

def get_url(**kwargs):
    return f'{_url}?{urlencode(kwargs)}'

def api(fnct, data):
    response = _session.post(API + fnct + "/", data=data)
    return response

def is_ok(xml):
    status = xml.find('status')
    return status is not None and status.text == 'OK'

def popinfo(message, heading=_addon.getAddonInfo('name'), icon=xbmcgui.NOTIFICATION_INFO, time=3000, sound=False):
    xbmcgui.Dialog().notification(heading, message, icon, time, sound=sound)

def login():
    username = _addon.getSetting('wsuser')
    password = _addon.getSetting('wspass')
    if not username or not password:
        popinfo(_addon.getLocalizedString(30101), sound=True)
        _addon.openSettings()
        return None
    response = api('salt', {'username_or_email': username})
    xml = ET.fromstring(response.content)
    if is_ok(xml):
        salt = xml.find('salt').text
        try:
            encrypted_pass = hashlib.sha1(md5crypt(password.encode('utf-8'), salt.encode('utf-8')).encode('utf-8')).hexdigest()
            pass_digest = hashlib.md5((username + REALM + encrypted_pass).encode('utf-8')).hexdigest()
        except Exception as e:
            xbmc.log(f"[login] Password hashing error: {e}", xbmc.LOGERROR)
            popinfo(_addon.getLocalizedString(30102), icon=xbmcgui.NOTIFICATION_ERROR, sound=True)
            return None
        response = api('login', {
            'username_or_email': username,
            'password': encrypted_pass,
            'digest': pass_digest,
            'keep_logged_in': 1
        })
        xml = ET.fromstring(response.content)
        if is_ok(xml):
            token = xml.find('token').text
            _addon.setSetting('token', token)
            return token
        else:
            popinfo(_addon.getLocalizedString(30102), icon=xbmcgui.NOTIFICATION_ERROR, sound=True)
            _addon.openSettings()
    else:
        popinfo(_addon.getLocalizedString(30102), icon=xbmcgui.NOTIFICATION_ERROR, sound=True)
        _addon.openSettings()
    return None

def revalidate():
    token = _addon.getSetting('token')
    if not token:
        return login()
    response = api('user_data', {'wst': token})
    xml = ET.fromstring(response.content)
    if is_ok(xml):
        vip = xml.find('vip').text
        if vip != '1':
            popinfo(_addon.getLocalizedString(30103), icon=xbmcgui.NOTIFICATION_WARNING)
        return token
    return login()

def todict(xml, skip=[]):
    result = {}
    for e in xml:
        if e.tag not in skip:
            value = e.text if len(list(e)) == 0 else todict(e, skip)
            if e.tag in result:
                if isinstance(result[e.tag], list):
                    result[e.tag].append(value)
                else:
                    result[e.tag] = [result[e.tag], value]
            else:
                result[e.tag] = value
    return result

def sizelize(txtsize, units=['B', 'KB', 'MB', 'GB']):
    if txtsize:
        size = float(txtsize)
        if size < 1024:
            return f"{size}{units[0]}"
        size /= 1024
        if size < 1024:
            return f"{int(round(size))}{units[1]}"
        size /= 1024
        if size < 1024:
            return f"{round(size, 2)}{units[2]}"
        size /= 1024
        return f"{round(size, 2)}{units[3]}"
    return str(txtsize)

def labelize(file):
    size = sizelize(file.get('size', file.get('sizelized', '?')))
    return f"{file['name']} ({size})"

def tolistitem(file, addcommands=[]):
    label = labelize(file)
    listitem = xbmcgui.ListItem(label=label)
    if 'img' in file:
        listitem.setArt({'thumb': file['img']})
    listitem.setInfo('video', {'title': label})
    listitem.setProperty('IsPlayable', 'true')
    commands = [
        (_addon.getLocalizedString(30211), f'RunPlugin({get_url(action="info", ident=file["ident"])})'),
        (_addon.getLocalizedString(30212), f'RunPlugin({get_url(action="download", ident=file["ident"])})')
    ]
    if addcommands:
        commands.extend(addcommands)
    listitem.addContextMenuItems(commands)
    return listitem

def ask(what):
    if what is None:
        what = ''
    kb = xbmc.Keyboard(what, _addon.getLocalizedString(30007))
    kb.doModal()
    if kb.isConfirmed():
        return kb.getText()
    return None

def loadsearch():
    history = []
    if not os.path.exists(_profile):
        try:
            os.makedirs(_profile)
        except Exception as e:
            xbmc.log(f"[loadsearch] Error creating profile dir: {e}", xbmc.LOGERROR)
            traceback.print_exc()
    try:
        with io.open(os.path.join(_profile, SEARCH_HISTORY), 'r', encoding='utf-8') as file:
            history = json.load(file)
    except Exception as e:
        xbmc.log(f"[loadsearch] Error loading history: {e}", xbmc.LOGERROR)
        traceback.print_exc()
    return history

def storesearch(what):
    if not what:
        return
    size = int(_addon.getSetting('shistory'))
    history = loadsearch()
    if what in history:
        history.remove(what)
    history.insert(0, what)
    if len(history) > size:
        history = history[:size]
    try:
        with io.open(os.path.join(_profile, SEARCH_HISTORY), 'w', encoding='utf-8') as file:
            json.dump(history, file, ensure_ascii=False)
    except Exception as e:
        xbmc.log(f"[storesearch] Error saving history: {e}", xbmc.LOGERROR)
        traceback.print_exc()

def removesearch(what):
    if not what:
        return
    history = loadsearch()
    if what in history:
        history.remove(what)
        try:
            with io.open(os.path.join(_profile, SEARCH_HISTORY), 'w', encoding='utf-8') as file:
                json.dump(history, file, ensure_ascii=False)
        except Exception as e:
            xbmc.log(f"[removesearch] Error saving history: {e}", xbmc.LOGERROR)
            traceback.print_exc()

def dosearch(token, what, category, sort, limit, offset, action):
    xbmc.log(f"[dosearch] ENTER what={what!r} cat={category} sort={sort} lim={limit} off={offset}", xbmc.LOGDEBUG)
    try:
        response = api('search', {
            'what': '' if what == NONE_WHAT else what,
            'category': category,
            'sort': sort,
            'limit': limit,
            'offset': offset,
            'wst': token,
            'maybe_removed': 'true'
        })
    except Exception as e:
        xbmc.log(f"[dosearch] HTTP error: {e}", xbmc.LOGERROR)
        popinfo("Webshare", f"HTTP chyba: {e}", icon=xbmcgui.NOTIFICATION_ERROR)
        return

    xbmc.log(f"[dosearch] HTTP status: {response.status_code}", xbmc.LOGDEBUG)
    xbmc.log(f"[dosearch] Response body: {response.content!r}", xbmc.LOGDEBUG)

    try:
        xml = ET.fromstring(response.content)
    except Exception as e:
        xbmc.log(f"[dosearch] XML parse error: {e}", xbmc.LOGERROR)
        popinfo("Webshare", f"Chyba parsování odpovědi: {e}", icon=xbmcgui.NOTIFICATION_ERROR)
        return

    if not is_ok(xml):
        msg = xml.find('message')
        msg = msg.text if msg is not None else 'Unknown'
        xbmc.log(f"[dosearch] API status not OK: {msg}", xbmc.LOGERROR)
        popinfo("Webshare", f"Chyba API: {msg}", icon=xbmcgui.NOTIFICATION_ERROR)
        return

    # Previous page
    if offset > 0:
        listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30206))
        listitem.setArt({'icon': 'DefaultAddonsSearch.png'})
        xbmcplugin.addDirectoryItem(
            _handle,
            get_url(action=action, what=what, category=category, sort=sort,
                    limit=limit, offset=max(0, offset - limit)),
            listitem, True
        )

    # Scoring results
    items = [todict(f) for f in xml.iter('file')]
    xbmc.log(f"[dosearch] Loaded {len(items)} items", xbmc.LOGDEBUG)

    query_tokens = clean_and_tokenize(what)
    scored = []
    for item in items:
        name_tokens = clean_and_tokenize(item.get('name', ''))
        rel = len(set(query_tokens) & set(name_tokens))
        stream = item.get('video', {}).get('stream', {})
        if isinstance(stream, list):
            stream = stream[0]
        try:
            w = int(stream.get('width', 0))
            h = int(stream.get('height', 0))
        except:
            w = h = 0
        qual = w * h
        scored.append((rel, qual, item))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    if scored:
        xbmc.log(f"[dosearch] Top score={scored[0][:2]}", xbmc.LOGDEBUG)

    for rel, qual, item in scored:
        xbmc.log(f"[dosearch] Render {item.get('name')} rel={rel} qual={qual}", xbmc.LOGDEBUG)
        commands = [(_addon.getLocalizedString(30214),
                     f'Container.Update({get_url(action=action, toqueue=item["ident"], what=what, category=category, sort=sort, limit=limit, offset=offset)})')]
        listitem = tolistitem(item, commands)

        # TMDb enrichment
        title = item.get('name') or item.get('title')
        tmdb_key = _addon.getSetting('tmdb_token')
        if title and tmdb_key:
            xbmc.log(f"[dosearch] TMDb lookup for {title!r}", xbmc.LOGDEBUG)
            tmdb_results = tmdb.search_movie(title) or []
            xbmc.log(f"[dosearch] TMDb results: {len(tmdb_results)}", xbmc.LOGDEBUG)
            if tmdb_results:
                meta = tmdb_results[0]
                poster = tmdb.get_poster_url(meta.get('poster_path'))
                if poster:
                    listitem.setArt({'thumb': poster})
                listitem.setInfo('video', {
                    'title': meta.get('title'),
                    'plot': meta.get('overview', ''),
                    'rating': meta.get('vote_average', 0)
                })

        xbmcplugin.addDirectoryItem(
            _handle,
            get_url(action=action, what=what, category=category,
                    sort=sort, limit=limit, offset=offset,
                    toqueue=item['ident']),
            listitem, False
        )

    # Next page
    total = xml.find('total')
    total = int(total.text) if total is not None else 0
    xbmc.log(f"[dosearch] total={total}", xbmc.LOGDEBUG)
    if offset + limit < total:
        listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30207))
        listitem.setArt({'icon': 'DefaultAddonsSearch.png'})
        xbmcplugin.addDirectoryItem(
            _handle,
            get_url(action=action, what=what, category=category,
                    sort=sort, limit=limit, offset=offset + limit),
            listitem, True
        )
    else:
        popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)

def search(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} \ {_addon.getLocalizedString(30201)}")
    token = revalidate()
    updateListing = False

    if 'remove' in params:
        removesearch(params['remove'])
        updateListing = True

    if 'toqueue' in params:
        toqueue(params['toqueue'], token)
        updateListing = True

    what = params.get('what')
    if 'ask' in params:
        slast = _addon.getSetting('slast')
        if slast != what:
            what = ask(what)
            if what is not None:
                storesearch(what)
            else:
                updateListing = True

    if what is not None:
        if 'offset' not in params:
            _addon.setSetting('slast', what)
        else:
            _addon.setSetting('slast', NONE_WHAT)
            updateListing = True

        category = params.get('category', CATEGORIES[int(_addon.getSetting('scategory'))])
        sort = params.get('sort', SORTS[int(_addon.getSetting('ssort'))])
        limit = int(params.get('limit', _addon.getSetting('slimit')))
        offset = int(params.get('offset', 0))
        tokens = clean_and_tokenize(what)
        what = ' '.join(tokens)
        dosearch(token, what, category, sort, limit, offset, 'search')
    else:
        _addon.setSetting('slast', NONE_WHAT)
        history = loadsearch()
        listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30205))
        listitem.setArt({'icon': 'DefaultAddSource.png'})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='search', ask=1), listitem, True)

        # Newest
        listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30208))
        listitem.setArt({'icon': 'DefaultAddonsRecentlyUpdated.png'})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='search', what=NONE_WHAT, sort=SORTS[1]), listitem, True)

        # Biggest
        listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30209))
        listitem.setArt({'icon': 'DefaultHardDisk.png'})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='search', what=NONE_WHAT, sort=SORTS[3]), listitem, True)

        for search in history:
            listitem = xbmcgui.ListItem(label=search)
            listitem.setArt({'icon': 'DefaultAddonsSearch.png'})
            commands = [(_addon.getLocalizedString(30213), f'Container.Update({get_url(action="search", remove=search)})')]
            listitem.addContextMenuItems(commands)
            xbmcplugin.addDirectoryItem(_handle, get_url(action='search', what=search, ask=1), listitem, True)
    xbmcplugin.endOfDirectory(_handle, updateListing=updateListing)

def queue(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} \ {_addon.getLocalizedString(30202)}")
    token = revalidate()
    updateListing = False

    if 'dequeue' in params:
        response = api('dequeue_file', {'ident': params['dequeue'], 'wst': token})
        xml = ET.fromstring(response.content)
        if is_ok(xml):
            popinfo(_addon.getLocalizedString(30106))
        else:
            popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
        updateListing = True

    response = api('queue', {'wst': token})
    xml = ET.fromstring(response.content)
    if is_ok(xml):
        for file in xml.iter('file'):
            item = todict(file)
            commands = [(_addon.getLocalizedString(30215), f'Container.Update({get_url(action="queue", dequeue=item["ident"])})')]
            listitem = tolistitem(item, commands)
            xbmcplugin.addDirectoryItem(_handle, get_url(action='play', ident=item['ident'], name=item['name']), listitem, False)
    else:
        popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
    xbmcplugin.endOfDirectory(_handle, updateListing=updateListing)

def toqueue(ident, token):
    response = api('queue_file', {'ident': ident, 'wst': token})
    xml = ET.fromstring(response.content)
    if is_ok(xml):
        popinfo(_addon.getLocalizedString(30105))
    else:
        popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)

def history(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} \ {_addon.getLocalizedString(30203)}")
    token = revalidate()
    updateListing = False

    if 'remove' in params:
        remove = params['remove']
        updateListing = True
        response = api('history', {'wst': token})
        xml = ET.fromstring(response.content)
        ids = []
        if is_ok(xml):
            for file in xml.iter('file'):
                if remove == file.find('ident').text:
                    download_id = file.find('download_id')
                    if download_id is not None:
                        ids.append(download_id.text)
        else:
            popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
        if ids:
            rr = api('clear_history', {'ids[]': ids, 'wst': token})
            xml = ET.fromstring(rr.content)
            if is_ok(xml):
                popinfo(_addon.getLocalizedString(30104))
            else:
                popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)

    if 'toqueue' in params:
        toqueue(params['toqueue'], token)
        updateListing = True

    response = api('history', {'wst': token})
    xml = ET.fromstring(response.content)
    files = []
    if is_ok(xml):
        for file in xml.iter('file'):
            item = todict(file, ['ended_at', 'download_id', 'started_at'])
            if item not in files:
                files.append(item)
        for file in files:
            commands = [
                (_addon.getLocalizedString(30213), f'Container.Update({get_url(action="history", remove=file["ident"])})'),
                (_addon.getLocalizedString(30214), f'Container.Update({get_url(action="history", toqueue=file["ident"])})')
            ]
            listitem = tolistitem(file, commands)
            xbmcplugin.addDirectoryItem(_handle, get_url(action='play', ident=file['ident'], name=file['name']), listitem, False)
    else:
        popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
    xbmcplugin.endOfDirectory(_handle, updateListing=updateListing)

def settings(params):
    _addon.openSettings()
    xbmcplugin.setResolvedUrl(_handle, False, xbmcgui.ListItem())

def infonize(data, key, process=str, showkey=True, prefix='', suffix='\n'):
    if key in data:
        return f"{prefix}{key.capitalize()}: {process(data[key])}{suffix}" if showkey else f"{prefix}{process(data[key])}{suffix}"
    return ''

def fpsize(fps):
    x = round(float(fps), 3)
    return str(int(x)) if int(x) == x else str(x)

def getinfo(ident, wst):
    response = api('file_info', {'ident': ident, 'wst': wst})
    xml = ET.fromstring(response.content)
    if not is_ok(xml):
        response = api('file_info', {'ident': ident, 'wst': wst, 'maybe_removed': 'true'})
        xml = ET.fromstring(response.content)
    if is_ok(xml):
        return xml
    popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
    return None

def info(params):
    xbmc.log(f'PARAMS: {params}', level=xbmc.LOGINFO)
    token = revalidate()
    xml = getinfo(params['ident'], token)
    if xml is not None:
        info = todict(xml)
        text = ''
        text += infonize(info, 'name')
        text += infonize(info, 'size', sizelize)
        text += infonize(info, 'type')
        text += infonize(info, 'width')
        text += infonize(info, 'height')
        text += infonize(info, 'format')
        text += infonize(info, 'fps', fpsize)
        text += infonize(info, 'bitrate', lambda x: sizelize(x, ['bps', 'Kbps', 'Mbps', 'Gbps']))
        if 'video' in info and 'stream' in info['video']:
            streams = info['video']['stream']
            if isinstance(streams, dict):
                streams = [streams]
            for stream in streams:
                text += 'Video stream: '
                text += infonize(stream, 'width', showkey=False, suffix='')
                text += infonize(stream, 'height', showkey=False, prefix='x', suffix='')
                text += infonize(stream, 'format', showkey=False, prefix=', ', suffix='')
                text += infonize(stream, 'fps', fpsize, showkey=False, prefix=', ', suffix='')
                text += '\n'
        if 'audio' in info and 'stream' in info['audio']:
            streams = info['audio']['stream']
            if isinstance(streams, dict):
                streams = [streams]
            for stream in streams:
                text += 'Audio stream: '
                text += infonize(stream, 'format', showkey=False, suffix='')
                text += infonize(stream, 'channels', prefix=', ', showkey=False, suffix='')
                text += infonize(stream, 'bitrate', lambda x: sizelize(x, ['bps', 'Kbps', 'Mbps', 'Gbps']), prefix=', ', showkey=False, suffix='')
                text += '\n'
        text += infonize(info, 'removed', lambda x: 'Yes' if x == '1' else 'No')
        xbmcgui.Dialog().textviewer(_addon.getAddonInfo('name'), text)

def getlink(ident, wst, dtype='video_stream'):
    duuid = _addon.getSetting('duuid')
    if not duuid:
        duuid = str(uuid.uuid4())
        _addon.setSetting('duuid', duuid)
    data = {'ident': ident, 'wst': wst, 'download_type': dtype, 'device_uuid': duuid}
    response = api('file_link', data)
    xml = ET.fromstring(response.content)
    if is_ok(xml):
        link = xml.find('link')
        return link.text if link is not None else None
    popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
    return None

def play(params):
    token = revalidate()
    link = getlink(params['ident'], token)
    if link is not None:
        headers = _session.headers.copy()
        headers.update({'Cookie': f'wst={token}'})
        link = f"{link}|{urlencode(headers)}"
        listitem = xbmcgui.ListItem(label=params['name'], path=link)
        listitem.setProperty('mimetype', 'application/octet-stream')
        xbmcplugin.setResolvedUrl(_handle, True, listitem)
    else:
        popinfo(_addon.getLocalizedString(30107), icon=xbmcgui.NOTIFICATION_WARNING)
        xbmcplugin.setResolvedUrl(_handle, False, xbmcgui.ListItem())

def join(path, file):
    return os.path.join(path, file)

def download(params):
    token = revalidate()
    where = _addon.getSetting('dfolder')
    if not where or not xbmcvfs.exists(where):
        popinfo(_addon.getLocalizedString(30101), sound=True)
        _addon.openSettings()
        return

    normalize = _addon.getSetting('dnormalize') == 'true'
    notify = _addon.getSetting('dnotify') == 'true'
    every = int(re.sub(r'[^\d]+', '', _addon.getSetting('dnevery') or '10')) or 10

    try:
        link = getlink(params['ident'], token, 'file_download')
        info = getinfo(params['ident'], token)
        if not info:
            return
        name = info.find('name').text
        if normalize:
            name = unidecode.unidecode(name)
        file_path = join(where, name)
        bf = xbmcvfs.File(file_path, 'w') if xbmcvfs.exists(where) else io.open(file_path, 'wb')
        response = _session.get(link, stream=True)
        total = response.headers.get('content-length')
        if total is None:
            popinfo(_addon.getLocalizedString(30301) + name, icon=xbmcgui.NOTIFICATION_WARNING, sound=True)
            bf.write(response.content)
        elif not notify:
            popinfo(_addon.getLocalizedString(30302) + name)
            bf.write(response.content)
        else:
            popinfo(_addon.getLocalizedString(30302) + name)
            dl = 0
            total = int(total)
            pct = total / 100
            lastpop = 0
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                bf.write(data)
                done = int(dl / pct)
                if done % every == 0 and lastpop != done:
                    popinfo(f"{done}% - {name}")
                    lastpop = done
        bf.close()
        popinfo(_addon.getLocalizedString(30303) + name, sound=True)
    except Exception as e:
        traceback.print_exc()
        popinfo(_addon.getLocalizedString(30304) + name, icon=xbmcgui.NOTIFICATION_ERROR, sound=True)
    finally:
        if 'bf' in locals():
            bf.close()

def loaddb(dbdir, file):
    try:
        with io.open(os.path.join(dbdir, file), 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('data', {})
    except Exception as e:
        xbmc.log(f"[loaddb] Error loading DB: {e}", xbmc.LOGERROR)
        traceback.print_exc()
        return {}

def db(params):
    token = revalidate()
    updateListing = False
    dbdir = os.path.join(_profile, 'db')
    if not os.path.exists(dbdir):
        link = getlink(BACKUP_DB, token)
        if not link:
            popinfo("Failed to retrieve backup DB", icon=xbmcgui.NOTIFICATION_ERROR)
            return
        dbfile = os.path.join(_profile, 'db.zip')
        try:
            with io.open(dbfile, 'wb') as bf:
                response = _session.get(link, stream=True)
                bf.write(response.content)
            with zipfile.ZipFile(dbfile, 'r') as zf:
                zf.extractall(_profile)
            os.unlink(dbfile)
        except Exception as e:
            xbmc.log(f"[db] Error extracting DB: {e}", xbmc.LOGERROR)
            popinfo("Failed to extract backup DB", icon=xbmcgui.NOTIFICATION_ERROR)
            return

    if 'toqueue' in params:
        toqueue(params['toqueue'], token)
        updateListing = True

    if 'file' in params and 'key' in params:
        data = loaddb(dbdir, params['file'])
        item = next((x for x in data if x['id'] == params['key']), None)
        if item is not None:
            for stream in item['streams']:
                commands = [(_addon.getLocalizedString(30214), f'Container.Update({get_url(action="db", file=params["file"], key=params["key"], toqueue=stream["ident"])})')]
                listitem = tolistitem({
                    'ident': stream['ident'],
                    'name': f"{stream['quality']} - {stream['lang']}{stream['ainfo']}",
                    'sizelized': stream['size']
                }, commands)
                xbmcplugin.addDirectoryItem(_handle, get_url(action='play', ident=stream['ident'], name=item['title']), listitem, False)
    elif 'file' in params:
        data = loaddb(dbdir, params['file'])
        for item in data:
            listitem = xbmcgui.ListItem(label=item['title'])
            if 'plot' in item:
                listitem.setInfo('video', {'title': item['title'], 'plot': item['plot']})
            xbmcplugin.addDirectoryItem(_handle, get_url(action='db', file=params['file'], key=item['id']), listitem, True)
    else:
        if os.path.exists(dbdir):
            dbfiles = [f for f in os.listdir(dbdir) if os.path.isfile(os.path.join(dbdir, f))]
            for dbfile in dbfiles:
                listitem = xbmcgui.ListItem(label=os.path.splitext(dbfile)[0])
                xbmcplugin.addDirectoryItem(_handle, get_url(action='db', file=dbfile), listitem, True)
    xbmcplugin.addSortMethod(_handle, xbmcplugin.SORT_METHOD_LABEL)
    xbmcplugin.endOfDirectory(_handle, updateListing=updateListing)

def menu():
    revalidate()
    xbmcplugin.setPluginCategory(_handle, _addon.getAddonInfo('name'))
    # Search
    listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30201))
    listitem.setArt({'icon': 'DefaultAddonsSearch.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='search'), listitem, True)

    # Newest
    listitem = xbmcgui.ListItem(label="Nově přidané")
    listitem.setArt({'icon': 'DefaultAddonsRecentlyUpdated.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='search', what=NONE_WHAT, sort=SORTS[1]), listitem, True)

    # Series
    listitem = xbmcgui.ListItem(label='Seriály')
    listitem.setArt({'icon': 'DefaultTVShows.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='series'), listitem, True)

    # Queue
    listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30202))
    listitem.setArt({'icon': 'DefaultPlaylist.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='queue'), listitem, True)

    # History
    listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30203))
    listitem.setArt({'icon': 'DefaultAddonsUpdates.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='history'), listitem, True)

    # Trakt Watchlist
    listitem = xbmcgui.ListItem(label='Moje watchlist (Trakt)')
    listitem.setArt({'icon': 'DefaultAddonTrakt.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='trakt_watchlist_menu'), listitem, True)

    # Trakt Authorization
    listitem = xbmcgui.ListItem(label='Autorizovat Trakt')
    listitem.setArt({'icon': 'DefaultAddonTrakt.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='trakt_auth'), listitem, True)

    # Backup DB
    if _addon.getSetting('experimental') == 'true':
        listitem = xbmcgui.ListItem(label='Backup DB')
        listitem.setArt({'icon': 'DefaultAddonsZip.png'})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='db'), listitem, True)

    # Settings
    listitem = xbmcgui.ListItem(label=_addon.getLocalizedString(30204))
    listitem.setArt({'icon': 'DefaultAddonService.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='settings'), listitem, False)

    xbmcplugin.endOfDirectory(_handle)

def series_menu(params):
    sm = series_manager.SeriesManager(_addon, _profile)
    series_manager.create_series_menu(sm, _handle, _addon.getSetting('tmdb_token'))

def series_search_tmdb(params):
    series_name = ask(None)
    if not series_name:
        xbmcplugin.endOfDirectory(_handle, succeeded=False)
        return
    tmdb = TMDB(_addon, _profile)
    selected = tmdb.FindSeries(series_name)
    if not selected:
        xbmcplugin.endOfDirectory(_handle, succeeded=False)
        return
    progress = xbmcgui.DialogProgress()
    progress.create("Webshare Cinema", f"Vyhledávám {selected['name']} / {selected['original_name']}")
    id = tmdb.get_series_details(selected['id'])
    result = tmdb.build_tmdb_series_structure(selected, id)
    folder_path = os.path.join(_profile, themoviedb.FOLDER_NAME)
    themoviedb.save_series_structure(result, folder_path)
    progress.close()
    xbmcplugin.endOfDirectory(_handle)

def series_search(params):
    token = revalidate()
    series_name = params.get('series_name') or ask(None)
    if not series_name:
        xbmcplugin.endOfDirectory(_handle, succeeded=False)
        return
    sm = series_manager.SeriesManager(_addon, _profile)
    progress = xbmcgui.DialogProgress()
    progress.create('Webshare Cinema', f'Vyhledavam serial {series_name}...')
    try:
        series_data = sm.search_series(series_name, api, token)
        if not series_data or not series_data.get('seasons'):
            progress.close()
            popinfo('Nenalezeny žádné epizody tohoto seriálu', icon=xbmcgui.NOTIFICATION_WARNING)
            xbmcplugin.endOfDirectory(_handle, succeeded=False)
            return
        progress.close()
        total_eps = sum(len(s) for s in series_data['seasons'].values())
        total_seasons = len(series_data['seasons'])
        popinfo(f'Nalezeno {total_eps} epizod v {total_seasons} sezonách')
        xbmc.executebuiltin(f"Container.Update({get_url(action='series_detail', series_name=series_name)},replaceWindow=true)")
    except Exception as e:
        progress.close()
        traceback.print_exc()
        popinfo(f'Chyba: {str(e)}', icon=xbmcgui.NOTIFICATION_ERROR)
        xbmcplugin.endOfDirectory(_handle, succeeded=False)

def series_detail(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} \ {params['series_name']}")
    sm = series_manager.SeriesManager(_addon, _profile)
    series_manager.create_seasons_menu(sm, _handle, params['series_name'])

def series_season(params):
    series_name = params['series_name']
    season = params['season']
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} \ {series_name} \ Rada {season}")
    sm = series_manager.SeriesManager(_addon, _profile)
    series_manager.create_episodes_menu(sm, _handle, series_name, season)

def series_refresh(params):
    token = revalidate()
    series_name = params['series_name']
    sm = series_manager.SeriesManager(_addon, _profile)
    progress = xbmcgui.DialogProgress()
    progress.create('Webshare Cinema', f'Aktualizuji data pro serial {series_name}...')
    try:
        series_data = sm.search_series(series_name, api, token)
        if not series_data or not series_data['seasons']:
            progress.close()
            popinfo('Nenalezeny zadne epizody tohoto serialu', icon=xbmcgui.NOTIFICATION_WARNING)
            xbmcplugin.endOfDirectory(_handle, succeeded=False)
            return
        progress.close()
        popinfo(f'Aktualizovano: {sum(len(season) for season in series_data["seasons"].values())} epizod v {len(series_data["seasons"])} sezonach')
        xbmc.executebuiltin(f'Container.Update({get_url(action="series_detail", series_name=series_name)})')
    except Exception as e:
        progress.close()
        traceback.print_exc()
        popinfo(f'Chyba: {str(e)}', icon=xbmcgui.NOTIFICATION_ERROR)
        xbmcplugin.endOfDirectory(_handle, succeeded=False)

def trakt_watchlist_menu(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} – Trakt Watchlist")
    li = xbmcgui.ListItem(label='Filmy z watchlistu')
    li.setArt({'icon': 'DefaultVideo.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='trakt_watchlist_movies'), li, True)
    li = xbmcgui.ListItem(label='Seriály z watchlistu')
    li.setArt({'icon': 'DefaultTVShows.png'})
    xbmcplugin.addDirectoryItem(_handle, get_url(action='trakt_watchlist_shows'), li, True)
    xbmcplugin.endOfDirectory(_handle)

def trakt_watchlist_movies(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} – Watchlist (Filmy)")
    token = _addon.getSetting('trakt_oauth_token')
    client_id = _addon.getSetting('trakt_client_id')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'trakt-api-version': '2',
        'trakt-api-key': client_id
    }
    try:
        r = requests.get('https://api.trakt.tv/users/me/watchlist/movies', headers=headers, timeout=10)
        r.raise_for_status()
    except Exception as e:
        xbmc.log(f"[trakt_watchlist_movies] Error: {e}", xbmc.LOGERROR)
        popinfo("Trakt", f"Chyba při načítání watchlistu: {e}", icon=xbmcgui.NOTIFICATION_ERROR)
        return
    for entry in r.json():
        movie = entry.get('movie', {})
        title = movie.get('title', 'Unknown')
        li = xbmcgui.ListItem(label=title)
        poster = movie.get('images', {}).get('poster', {}).get('full')
        if poster:
            li.setArt({'thumb': poster})
        li.setInfo('video', {'title': title, 'plot': movie.get('overview', '')})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='search', what=title), li, True)
    xbmcplugin.endOfDirectory(_handle)

def trakt_watchlist_shows(params):
    xbmcplugin.setPluginCategory(_handle, f"{_addon.getAddonInfo('name')} – Watchlist (Seriály)")
    token = _addon.getSetting('trakt_oauth_token')
    client_id = _addon.getSetting('trakt_client_id')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'trakt-api-version': '2',
        'trakt-api-key': client_id
    }
    try:
        r = requests.get('https://api.trakt.tv/users/me/watchlist/shows', headers=headers, timeout=10)
        r.raise_for_status()
    except Exception as e:
        xbmc.log(f"[trakt_watchlist_shows] Error: {e}", xbmc.LOGERROR)
        popinfo("Trakt", f"Chyba při načítání watchlistu: {e}", icon=xbmcgui.NOTIFICATION_ERROR)
        return
    for entry in r.json():
        show = entry.get('show', {})
        title = show.get('title', 'Unknown')
        li = xbmcgui.ListItem(label=title)
        poster = show.get('images', {}).get('poster', {}).get('full')
        if poster:
            li.setArt({'thumb': poster})
        li.setInfo('video', {'title': title, 'plot': show.get('overview', '')})
        xbmcplugin.addDirectoryItem(_handle, get_url(action='series_search', series_name=title), li, True)
    xbmcplugin.endOfDirectory(_handle)

def router(paramstring):
    params = dict(parse_qsl(paramstring))
    if params:
        action = params.get('action')
        if action == 'search':
            search(params)
        elif action == 'queue':
            queue(params)
        elif action == 'history':
            history(params)
        elif action == 'settings':
            settings(params)
            xbmc.executebuiltin("Container.Refresh")
        elif action == 'info':
            info(params)
        elif action == 'play':
            play(params)
        elif action == 'download':
            download(params)
        elif action == 'db':
            db(params)
        elif action == 'trakt_auth':
            code = trakt_authorize()
            if code:
                trakt_get_token(code)
            menu()
        elif action == 'trakt_watchlist_menu':
            trakt_watchlist_menu(params)
        elif action == 'trakt_watchlist_movies':
            trakt_watchlist_movies(params)
        elif action == 'trakt_watchlist_shows':
            trakt_watchlist_shows(params)
        elif action == 'series':
            series_menu(params)
        elif action == 'series_search':
            series_search(params)
        elif action == 'series_search_tmdb':
            series_search_tmdb(params)
        elif action == 'series_detail':
            series_detail(params)
        elif action == 'series_season':
            series_season(params)
        elif action == 'series_refresh':
            series_refresh(params)
        elif action == 'series_delete':
            series_name = params.get('series_name')
            if series_name:
                sm = series_manager.SeriesManager(_addon, _profile)
                sm.delete_series(series_name)
                xbmc.executebuiltin("Container.Refresh")
        else:
            menu()
    else:
        menu()

if __name__ == '__main__':
    router(sys.argv[2][1:])
