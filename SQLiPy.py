"""
Name:           SQLiPy
Version:        0.9.0
Date:           10/28/2026
Author:         Josh Berry - josh.berry@codewatch.org (original SQLiPy)
Github:         https://github.com/codewatchorg/sqlipy
0.9.0:          Tr0j4n1 - https://github.com/Tr0j4n1/sqlipy

Description:    This plugin leverages the SQLMap API to initiate SQLMap scans against the target.

0.9.0 changes (Tr0j4n1):
- New UI built with layout managers: it resizes, follows Burp's theme and font size, and nothing is cut off.
- Three tabs (Scan, Tasks, API). Rarely used options are folded and only one folded section is open at a time.
- The API start and all API calls run in the background, so Burp no longer freezes.
- The Tasks tab shows the status, results, log and sqlmap command of every task.
- Dump dialog: list databases, list tables, dump a table, a database or everything. Its folded Speed and log section changes threads, timeout, verbose level etc. per dump.
- Verbose level (sqlmap -v 1 to 6) on the Scan tab and in the Dump dialog. Payloads and HTTP traffic show in the task log.
- Dumped data tab: view the rows, copy a cell, row, column or table, or save as CSV.
- Results ignore sqlmap's in-progress console text, so lists are no longer split into characters.

This plugin requires Jython 2.7 (up to 2.7.2).

I used this blog post to quickly understand and leverage the SQLMap API (thrilled that someone figured this out for me):
http://volatile-minds.blogspot.com/2013/04/unofficial-sqlmap-restful-api.html

The following Burp plugins were reviewed to help develop this:
- Payload Parser: https://github.com/infodel
- Burp SAMl: https://github.com/Meatballs1/burp_saml
- ActiveScan++:
- WCF Binary SOAP Handler: http://blog.securityps.com/2013/02/burp-suite-plugin-view-and-modify-wcf.html
- WSDL Wizard: https://github.com/SmeegeSec/WSDLWizard/blob/master/WSDLWizard.py
- co2: https://code.google.com/p/burp-co2/

"""

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab
from burp import IScanIssue
from burp import IExtensionStateListener
from javax import swing
from javax.swing import SwingUtilities
from javax.swing.border import EmptyBorder
from javax.swing.event import ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import DefaultTableModel
from javax.swing.table import DefaultTableCellRenderer
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Dimension
from java.awt import Font
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import GridLayout
from java.awt import Insets
from java.awt import LayoutManager
from java.awt import RenderingHints
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from java.awt.event import MouseAdapter
from java.beans import PropertyChangeListener
from javax.swing import UIManager
from java.io import BufferedReader
from java.io import File
from java.io import InputStreamReader
from java.lang import ProcessBuilder
from java.lang import Runnable
from java.lang import String
from java.lang import System
from jarray import array
from collections import OrderedDict
from StringIO import StringIO
import base64
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import urllib
import urllib2
import zipfile

VERSION = '0.9.0'
BAPP_UUID = 'f154175126a04bfe8edc6056f340f52e'
ANSWERS = 'crack=N,dict=N,continue=Y,quit=N'
IS_WINDOWS = 'Windows' in System.getProperty('os.name')

GREEN = Color(46, 160, 67)
RED = Color(218, 68, 68)
AMBER = Color(222, 150, 30)
GREY = Color(140, 140, 140)
ORANGE = Color(232, 88, 42)

STATUS_COLORS = {'Running': AMBER, 'Vulnerable': RED, 'Done': GREEN, 'Not vulnerable': GREY, 'Stopped': GREY, 'Failed': GREY}

DBMS_VALUES = ['Any', 'MySQL', 'Oracle', 'PostgreSQL', 'Microsoft SQL Server', 'Microsoft Access', 'SQLite', 'Firebird', 'Sybase', 'SAP MaxDB', 'DB2', 'Informix', 'MariaDB', 'Percona', 'MemSQL', 'TiDB', 'CockroachDB', 'HSQLDB', 'H2', 'MonetDB', 'Apache Derby', 'Amazon Redshift', 'Vertica', 'Mckoi', 'Presto', 'Altibase', 'MimerSQL', 'CrateDB', 'Greenplum', 'Drizzle', 'Apache Ignite', 'Cubrid', 'InterSystems Cache', 'IRIS', 'eXtremeDB', 'FrontBase']

# Scan tab ticks, in display order: (sqlmap API option, label)
ENUM_OPTIONS = [('getCurrentUser', 'Current user'), ('getCurrentDb', 'Current DB'), ('getHostname', 'Hostname'), ('isDba', 'Is DBA'),
                ('getUsers', 'Users'), ('getPasswordHashes', 'Password hashes'), ('getPrivileges', 'Privileges'), ('getRoles', 'Roles'),
                ('getDbs', 'Databases'), ('getTables', 'Tables'), ('getColumns', 'Columns'), ('getSchema', 'Schema'),
                ('getCount', 'Row counts')]

# Speed row on the Scan tab and in the Dump dialog: (sqlmap API option, label, choices, default)
SPEED_OPTIONS = [('threads', 'Threads', range(1, 11), 1), ('delay', 'Delay (s)', range(0, 6), 0),
                 ('timeout', 'Timeout (s)', [1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60], 30),
                 ('retries', 'Retries', range(1, 11), 3), ('timeSec', 'Time-sec', range(1, 16), 5)]

# sqlmap -v levels. Each level also logs everything the levels below it log. sqlmap's default is 1.
# Level 0 is left out: it hides the log lines that name the CSV files, so a multi-table dump would show only its last table.
VERBOSE_LEVELS = OrderedDict([(1, 'Info (default)'), (2, 'Debug'), (3, 'Payloads'), (4, 'HTTP requests'),
                              (5, 'Response headers'), (6, 'Response bodies')])

# Options a follow-up task (Dump or List tables) does not inherit from its parent scan
ENUM_KEYS = [key for key, label in ENUM_OPTIONS] + ['getBanner', 'dumpTable', 'dumpAll', 'excludeSysDbs', 'db', 'tbl', 'col', 'dumpWhere', 'limitStart', 'limitStop']

# sqlmap API option -> command line flag, used to show the equivalent sqlmap command
CLI_FLAGS = [('url', '-u'), ('method', '--method'), ('data', '--data'), ('cookie', '--cookie'), ('agent', '--user-agent'),
             ('referer', '--referer'), ('headers', '--headers'), ('authType', '--auth-type'), ('authCred', '--auth-cred'),
             ('ignoreCode', '--ignore-code'), ('proxy', '--proxy'), ('tor', '--tor'), ('torType', '--tor-type'), ('torPort', '--tor-port'),
             ('testParameter', '-p'), ('dbms', '--dbms'), ('os', '--os'), ('tamper', '--tamper'), ('level', '--level'), ('risk', '--risk'),
             ('technique', '--technique'), ('textOnly', '--text-only'), ('hpp', '--hpp'), ('threads', '--threads'), ('delay', '--delay'),
             ('timeout', '--timeout'), ('retries', '--retries'), ('timeSec', '--time-sec'), ('verbose', '-v'), ('getBanner', '-b'),
             ('getCurrentUser', '--current-user'), ('getCurrentDb', '--current-db'), ('getHostname', '--hostname'), ('isDba', '--is-dba'),
             ('getUsers', '--users'), ('getPasswordHashes', '--passwords'), ('getPrivileges', '--privileges'), ('getRoles', '--roles'),
             ('getDbs', '--dbs'), ('getTables', '--tables'), ('getColumns', '--columns'), ('getSchema', '--schema'), ('getCount', '--count'),
             ('dumpTable', '--dump'), ('dumpAll', '--dump-all'), ('excludeSysDbs', '--exclude-sysdbs'), ('db', '-D'), ('tbl', '-T'),
             ('col', '-C'), ('dumpWhere', '--where'), ('limitStart', '--start'), ('limitStop', '--stop'), ('batch', '--batch'),
             ('answers', '--answers')]

CSV_LOG = re.compile(r"table '(.+?)' dumped to CSV file '(.+)'")

def say(msg):
  # Burp's output stream rejects non-ASCII unicode, so encode first
  if isinstance(msg, unicode):
    msg = msg.encode('utf-8', 'replace')
  print msg

def guarded(fn, *args):
  try:
    return fn(*args)
  except:
    say(traceback.format_exc())

class Later(Runnable):
  def __init__(self, fn, args):
    self.fn = fn
    self.args = args

  def run(self):
    guarded(self.fn, *self.args)

def onEdt(fn, *args):
  SwingUtilities.invokeLater(Later(fn, args))

def inBackground(fn, *args):
  t = threading.Thread(target=guarded, args=(fn,) + args)
  t.daemon = True
  t.start()
  return t

def errorText():
  ex = sys.exc_info()[1]
  return (unicode(ex) or ex.__class__.__name__) if ex is not None else 'unknown error'

def esc(value):
  if value is None:
    return 'NULL'
  if not isinstance(value, basestring):
    value = unicode(value)
  return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def cliQuote(value):
  value = unicode(value).replace('"', '\\"').replace('\r', '').replace('\n', '\\n')
  return '"' + value + '"'

def toCommand(opts):
  parts = ['sqlmap']
  shown = dict(opts)
  shown['batch'] = True
  for key, flag in CLI_FLAGS:
    value = shown.get(key)
    if value is None or value is False or value == '':
      continue
    if value is True:
      parts.append(flag)
    elif flag.startswith('--'):
      parts.append(flag + '=' + cliQuote(value))
    else:
      parts.append(flag + ' ' + cliQuote(value))
  return ' '.join(parts)

def parseCsv(raw):
  if raw.startswith('\xef\xbb\xbf'):
    raw = raw[3:]
  rows = [r for r in csv.reader(StringIO(raw)) if r]
  if not rows:
    return None
  decode = lambda cell: cell.decode('utf-8', 'replace')
  return ([decode(c) for c in rows[0]], [[decode(c) for c in r] for r in rows[1:]])

class Results(object):
  # What sqlmap returned for one task, parsed from /scan/<id>/data
  def __init__(self):
    self.vulnerable = False
    self.target = None
    self.injections = []
    self.dbms = ''
    self.facts = []
    self.currentDb = None
    self.users = []
    self.perUser = []
    self.dbs = []
    self.tables = OrderedDict()
    self.columns = OrderedDict()
    self.counts = None
    self.dumps = OrderedDict()
    self.other = []
    self.errors = []

def parseResults(data, errors):
  r = Results()
  r.errors = [e for e in (errors or []) if e]

  for item in data or []:
    # Status 0 rows are console text sqlmap printed while a step ran (warnings, progress dots), not results
    if item.get('status') != 1:
      continue
    kind = item.get('type')
    value = item.get('value')

    if kind == 0:
      r.vulnerable = True
      r.target = value
    elif kind == 1:
      r.vulnerable = True
      r.injections = value or []
      for inj in r.injections:
        dbms = inj.get('dbms')
        if dbms:
          r.dbms = ' or '.join(dbms) if isinstance(dbms, list) else dbms
    elif kind == 2:
      r.facts.append(('Fingerprint', value))
    elif kind == 3:
      r.facts.append(('Banner', value))
    elif kind == 4:
      r.facts.append(('Current user', value))
    elif kind == 5:
      r.facts.append(('Current DB', value))
      r.currentDb = value
    elif kind == 6:
      r.facts.append(('Hostname', value if value is not None else 'Enumeration failed'))
    elif kind == 7:
      r.facts.append(('Is DBA', 'Yes' if value is True else 'No'))
    elif kind in (8, 12) and value is not None and not isinstance(value, list):
      r.other.append((kind, value))
    elif kind in (9, 10, 11, 13, 14, 15) and value is not None and not isinstance(value, dict):
      r.other.append((kind, value))
    elif kind == 8:
      r.users = value or []
    elif kind in (9, 10, 11):
      title = {9: 'Password hashes', 10: 'Privileges', 11: 'Roles'}[kind]
      r.perUser.append((title, value or {}))
    elif kind == 12:
      r.dbs = value or []
    elif kind == 13:
      for db, tables in (value or {}).items():
        r.tables[db] = tables or []
    elif kind in (14, 15):
      for db, tables in (value or {}).items():
        r.columns.setdefault(db, OrderedDict()).update(tables or {})
    elif kind == 16:
      r.counts = value
    elif kind == 17 and value:
      infos = value.get('__infos__') or {}
      cols = [k for k in value.keys() if k != '__infos__']
      values = [value[c].get('values') or [] for c in cols]
      count = max([len(v) for v in values]) if values else 0
      rows = [[(values[j][i] if i < len(values[j]) else '') for j in range(len(cols))] for i in range(count)]
      r.dumps['%s.%s' % (infos.get('db') or 'All', infos.get('table'))] = (cols, rows)
    elif value not in (None, '', [], {}):
      r.other.append((kind, value))

  return r

def htmlList(items):
  if isinstance(items, basestring):
    items = [items]
  return '<ul>' + ''.join(['<li>' + esc(i) + '</li>' for i in items]) + '</ul>'

def htmlValue(value):
  if isinstance(value, dict):
    return '<ul>' + ''.join(['<li><b>' + esc(k) + '</b>' + htmlValue(v) + '</li>' for k, v in value.items()]) + '</ul>'
  if isinstance(value, list):
    return '<ul>' + ''.join(['<li>' + htmlValue(v) + '</li>' for v in value]) + '</ul>'
  return ' ' + esc(value)

def resultsHtml(task):
  r = task.result
  out = []

  if r is None:
    if task.status == 'Running':
      out.append('<p>sqlmap is running. Results show here when it finds something. Follow the progress in the Log tab.</p>')
    else:
      out.append('<p>No results for this task.</p>')
    return '<html><body>' + ''.join(out) + '</body></html>'

  if r.vulnerable:
    out.append('<p><b>SQL injection found</b>' + (' &nbsp;&middot;&nbsp; back-end: ' + esc(r.dbms) if r.dbms else '') + '</p>')
  elif task.status == 'Running':
    out.append('<p>sqlmap is running. Nothing found yet.</p>')
  elif task.status in ('Failed', 'Stopped'):
    out.append('<p><b>' + esc(task.status) + '.</b> Read the Log tab for the reason.</p>')
  else:
    out.append('<p><b>No injection found.</b> Try a higher Level or Risk under Detection on the Scan tab.</p>')

  if r.target:
    out.append('<p>URL: ' + esc(r.target.get('url')) + '</p>')

  if r.injections:
    out.append('<h3>Injection points</h3><ul>')
    for inj in r.injections:
      out.append('<li><b>' + esc(inj.get('parameter')) + '</b> (' + esc(inj.get('place')) + ')<ul>')
      for k, tech in (inj.get('data') or {}).items():
        out.append('<li>' + esc(tech.get('title')) + '<br><code>' + esc(tech.get('payload')) + '</code></li>')
      out.append('</ul></li>')
    out.append('</ul>')

  if r.facts:
    out.append('<h3>Details</h3><table cellpadding="2">')
    for label, value in r.facts:
      out.append('<tr><td valign="top"><b>' + esc(label) + '</b></td><td>' + esc(value) + '</td></tr>')
    out.append('</table>')

  if r.dbs:
    out.append('<h3>Databases (%d)</h3>' % len(r.dbs) + htmlList(r.dbs))

  for db, tables in r.tables.items():
    out.append('<h3>Tables in %s (%d)</h3>' % (esc(db), len(tables)) + htmlList(tables))

  for db, tables in r.columns.items():
    for table, cols in tables.items():
      items = ['%s  %s' % (c, t or '') for c, t in (cols or {}).items()]
      out.append('<h3>Columns in %s.%s</h3>' % (esc(db), esc(table)) + htmlList(items))

  if r.counts:
    out.append('<h3>Row counts</h3>' + htmlValue(r.counts))

  if r.users:
    out.append('<h3>Users (%d)</h3>' % len(r.users) + htmlList(r.users))

  for title, values in r.perUser:
    out.append('<h3>' + esc(title) + '</h3>' + htmlValue(values))

  if r.dumps:
    out.append('<h3>Dumped tables</h3>')
    out.append(htmlList(['%s  (%d rows)' % (k, len(v[1])) for k, v in r.dumps.items()]))
    out.append('<p>Open the <b>Dumped data</b> tab to see the rows.</p>')

  for kind, value in r.other:
    out.append('<h3>Other output (type %s)</h3>' % esc(kind) + htmlValue(value))

  if r.errors:
    out.append('<h3>Errors</h3>' + htmlList(r.errors))

  return '<html><body>' + ''.join(out) + '</body></html>'

def issueHtml(r):
  out = ['The application has been found to be vulnerable to SQL injection by SQLMap.<br><br>']
  if r.target:
    out.append('<b>URL:</b> ' + esc(r.target.get('url')) + '<br>')
  if r.dbms:
    out.append('<b>Back-end DBMS:</b> ' + esc(r.dbms) + '<br>')
  for inj in r.injections:
    out.append('<br><b>Parameter:</b> ' + esc(inj.get('parameter')) + ' (' + esc(inj.get('place')) + ')<ul>')
    for k, tech in (inj.get('data') or {}).items():
      out.append('<li>' + esc(tech.get('title')) + ': ' + esc(tech.get('payload')) + '</li>')
    out.append('</ul>')
  if r.facts:
    out.append('<br><b>Enumerated data:</b><ul>')
    for label, value in r.facts:
      out.append('<li>' + esc(label) + ': ' + esc(value) + '</li>')
    out.append('</ul>')
  if r.dbs:
    out.append('<b>Databases:</b><ul>' + ''.join(['<li>' + esc(d) + '</li>' for d in r.dbs]) + '</ul>')
  return ''.join(out)

class SqlMapScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.vulnurl = url
        self.HttpMessages = httpMessages
        self.vulnname = name
        self.vulndetail = detail
        self.vulnsev = severity
        self.vulnconf = confidence
        return

    def getUrl(self):
        return self.vulnurl

    def getIssueName(self):
        return self.vulnname

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.vulnsev

    def getConfidence(self):
        return self.vulnconf

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.vulndetail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

class ScanTask(object):
  def __init__(self, taskid, job, url, options, message, messageUrl, parent):
    self.id = taskid
    self.job = job
    self.url = url
    self.options = options
    self.cmd = toCommand(options)
    self.message = message
    self.messageUrl = messageUrl
    self.parent = parent
    self.started = time.strftime('%H:%M:%S')
    self.status = 'Running'
    self.log = []
    self.result = None
    self.reported = False

# ---------- Small Swing helpers ----------

class Action(ActionListener):
  def __init__(self, fn):
    self.fn = fn

  def actionPerformed(self, event):
    guarded(self.fn, event)

class Selection(ListSelectionListener):
  def __init__(self, fn):
    self.fn = fn

  def valueChanged(self, event):
    if not event.getValueIsAdjusting():
      guarded(self.fn)

class Dot(swing.Icon):
  # Coloured status dot. Drawn, so it does not depend on the font having a glyph for it.
  def __init__(self, color, size=10):
    self.color = color
    self.size = size

  def getIconWidth(self):
    return self.size

  def getIconHeight(self):
    return self.size

  def paintIcon(self, c, g, x, y):
    g2 = g.create()
    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    g2.setColor(self.color)
    g2.fillOval(x, y, self.size, self.size)
    g2.dispose()

class Chevron(swing.Icon):
  # Fold marker for section headers: points right when folded, down when open
  def __init__(self, opened):
    self.opened = opened

  def getIconWidth(self):
    return 10

  def getIconHeight(self):
    return 10

  def paintIcon(self, c, g, x, y):
    g2 = g.create()
    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    g2.setColor(c.getForeground())
    if self.opened:
      xs, ys = [x, x + 10, x + 5], [y + 2, y + 2, y + 8]
    else:
      xs, ys = [x + 2, x + 8, x + 2], [y, y + 5, y + 10]
    g2.fillPolygon(array(xs, 'i'), array(ys, 'i'), 3)
    g2.dispose()

class PrimaryStyle(PropertyChangeListener):
  # Orange main action while enabled, the normal look while disabled
  def propertyChange(self, event):
    self.apply(event.getSource())

  def apply(self, button):
    if button.isEnabled():
      button.setBackground(ORANGE)
      button.setForeground(Color.WHITE)
    else:
      button.setBackground(UIManager.getColor('Button.background'))
      button.setForeground(UIManager.getColor('Button.foreground'))

class CopyMenu(MouseAdapter):
  # Right-click menu on the dumped rows table
  ITEMS = [('Copy cell', 'cell'), ('Copy row', 'row'), ('Copy column', 'column'), ('Copy table with headers', 'table')]

  def __init__(self, ext):
    self.ext = ext

  def mousePressed(self, event):
    self.maybeShow(event)

  def mouseReleased(self, event):
    self.maybeShow(event)

  def maybeShow(self, event):
    if not event.isPopupTrigger():
      return
    table = event.getSource()
    row, col = table.rowAtPoint(event.getPoint()), table.columnAtPoint(event.getPoint())
    if row < 0 or col < 0:
      return
    if not table.isCellSelected(row, col):
      table.changeSelection(row, col, False, False)
    menu = swing.JPopupMenu()
    for label, what in self.ITEMS:
      menu.add(swing.JMenuItem(label, actionPerformed=lambda e, w=what: self.ext.copyDump(w, row, col)))
    menu.show(table, event.getX(), event.getY())

class StatusRenderer(DefaultTableCellRenderer):
  def setValue(self, value):
    self.setText(value or '')
    self.setIcon(Dot(STATUS_COLORS.get(value, GREY), 8) if value else None)
    self.setIconTextGap(6)

class LevelRenderer(swing.ListCellRenderer):
  # Shows a verbose level as "3 - Payloads". The look and feel's own renderer still draws it.
  def __init__(self, inner):
    self.inner = inner

  def getListCellRendererComponent(self, lst, value, index, selected, focused):
    c = self.inner.getListCellRendererComponent(lst, value, index, selected, focused)
    if value in VERBOSE_LEVELS and isinstance(c, swing.JLabel):
      c.setText('%d - %s' % (value, VERBOSE_LEVELS[value]))
    return c

class ReadOnlyModel(DefaultTableModel):
  def isCellEditable(self, row, column):
    return False

class ScrollPage(swing.JPanel, swing.Scrollable):
  # Page that scrolls up and down only and always fills the width of the view
  def getPreferredScrollableViewportSize(self):
    return self.getPreferredSize()

  def getScrollableUnitIncrement(self, visible, orientation, direction):
    return 16

  def getScrollableBlockIncrement(self, visible, orientation, direction):
    return max(16, visible.height - 40)

  def getScrollableTracksViewportWidth(self):
    return True

  def getScrollableTracksViewportHeight(self):
    return False

class CappedWidthLayout(LayoutManager):
  # Lays out one child left-aligned, at its preferred height and at most maxWidth wide
  def __init__(self, maxWidth):
    self.maxWidth = maxWidth

  def addLayoutComponent(self, name, comp):
    pass

  def removeLayoutComponent(self, comp):
    pass

  def preferredLayoutSize(self, parent):
    ins = parent.getInsets()
    w = h = 0
    for c in parent.getComponents():
      d = c.getPreferredSize()
      w = max(w, min(d.width, self.maxWidth))
      h = max(h, d.height)
    return Dimension(w + ins.left + ins.right, h + ins.top + ins.bottom)

  def minimumLayoutSize(self, parent):
    d = self.preferredLayoutSize(parent)
    return Dimension(0, d.height)

  def layoutContainer(self, parent):
    ins = parent.getInsets()
    width = min(parent.getWidth() - ins.left - ins.right, self.maxWidth)
    for c in parent.getComponents():
      c.setBounds(ins.left, ins.top, max(0, width), c.getPreferredSize().height)

class Ruler(swing.JComponent):
  # Zero-height spacer that keeps the label column as wide as its widest label, folded or not
  labels = None

  def getPreferredSize(self):
    w = 0
    for label in self.labels or []:
      w = max(w, label.getPreferredSize().width)
    return Dimension(w, 0)

  def getMinimumSize(self):
    return self.getPreferredSize()

def hbox(*items):
  # Lay items out left to right. An item is a component, a string (shown as a label) or (component, weight).
  panel = swing.JPanel(GridBagLayout())
  panel.setOpaque(False)
  x = 0
  stretches = False
  afterLabel = False
  for item in items:
    weight = 0.0
    if isinstance(item, tuple):
      item, weight = item
    isLabel = isinstance(item, basestring)
    if isLabel:
      item = swing.JLabel(item)
    c = GridBagConstraints()
    c.gridx = x
    c.gridy = 0
    c.weightx = weight
    c.fill = GridBagConstraints.HORIZONTAL if weight else GridBagConstraints.NONE
    c.anchor = GridBagConstraints.WEST
    c.insets = Insets(0, 0 if x == 0 else (6 if afterLabel else (16 if isLabel else 8)), 0, 0)
    panel.add(item, c)
    stretches = stretches or bool(weight)
    afterLabel = isLabel
    x += 1
  if not stretches:
    c = GridBagConstraints()
    c.gridx = x
    c.weightx = 1.0
    panel.add(swing.Box.createHorizontalGlue(), c)
  return panel

class Form(object):
  # Two-column grid: labels on the left, fields on the right. Rows can be hidden to fold a section.
  def __init__(self):
    self.panel = swing.JPanel(GridBagLayout())
    self.panel.setOpaque(False)
    self.y = 0
    self.labels = []

  def put(self, comp, x, width=1, weightx=0.0, fill=GridBagConstraints.NONE, anchor=GridBagConstraints.WEST, top=3, bottom=3, right=0):
    c = GridBagConstraints()
    c.gridx = x
    c.gridy = self.y
    c.gridwidth = width
    c.weightx = weightx
    c.fill = fill
    c.anchor = anchor
    c.insets = Insets(top, 0, bottom, right)
    self.panel.add(comp, c)
    return comp

  def full(self, comp, top=3, bottom=3):
    self.put(comp, 0, width=2, weightx=1.0, fill=GridBagConstraints.HORIZONTAL, top=top, bottom=bottom)
    self.y += 1
    return [comp]

  def row(self, label, comp, tall=False, stretch=True):
    lab = swing.JLabel(label)
    self.labels.append(lab)
    self.put(lab, 0, anchor=GridBagConstraints.NORTHWEST if tall else GridBagConstraints.WEST, right=14, top=7 if tall else 3)
    self.put(comp, 1, weightx=1.0, fill=GridBagConstraints.HORIZONTAL if stretch else GridBagConstraints.NONE)
    self.y += 1
    return [lab, comp]

  def finish(self):
    ruler = Ruler()
    ruler.labels = self.labels
    self.put(ruler, 0, top=0, bottom=0, right=14)
    self.y += 1

def speedRows(form, values=None):
  # The Threads ... Time-sec row and the Verbose row. values (sqlmap option -> number) sets the boxes, else the defaults.
  # Returns (sqlmap option -> combo box, the rows' components).
  values = values or {}
  boxes = OrderedDict()
  items = []
  for key, label, choices, default in SPEED_OPTIONS:
    boxes[key] = swing.JComboBox(choices)
    boxes[key].setSelectedItem(values.get(key, default))
    if items:
      items.append(label)
    items.append(boxes[key])
  verbose = boxes['verbose'] = swing.JComboBox(list(VERBOSE_LEVELS.keys()))
  verbose.setRenderer(LevelRenderer(verbose.getRenderer()))
  verbose.setSelectedItem(values.get('verbose', 1))
  return boxes, (form.row('Threads', hbox(*items)) +
                 form.row('Verbose', hbox(verbose, '3 and up show payloads and HTTP traffic in the task log.')))

class Section(object):
  def __init__(self, accordion, button):
    self.accordion = accordion
    self.button = button
    self.rows = []
    self.opened = False

  def add(self, comps):
    self.rows.extend(comps)
    for c in comps:
      c.setVisible(self.opened)

  def setOpen(self, opened):
    self.opened = opened
    self.button.setIcon(Chevron(opened))
    for c in self.rows:
      c.setVisible(opened)

class Accordion(object):
  # Folded sections where opening one closes the others. Section buttons are added to bold for the font pass.
  def __init__(self, bold, form):
    self.bold = bold
    self.form = form
    self.sections = []

  def section(self, title):
    self.form.full(swing.JSeparator(), top=12, bottom=2)
    button = swing.JButton(title)
    button.setBorderPainted(False)
    button.setContentAreaFilled(False)
    button.setFocusPainted(False)
    button.setHorizontalAlignment(swing.SwingConstants.LEFT)
    button.setBorder(EmptyBorder(4, 0, 4, 0))
    button.setIconTextGap(8)
    self.bold.append(button)
    section = Section(self, button)
    button.addActionListener(Action(lambda e, s=section: self.toggle(s)))
    section.setOpen(False)
    self.sections.append(section)
    self.form.full(button, top=0, bottom=0)
    return section

  def toggle(self, section):
    opening = not section.opened
    for s in self.sections:
      s.setOpen(s is section and opening)
    self.form.panel.revalidate()
    self.form.panel.repaint()
    # A dialog does not grow by itself when a section opens
    window = SwingUtilities.getWindowAncestor(self.form.panel)
    if isinstance(window, swing.JDialog):
      window.pack()

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

  # Implement IBurpExtender
  def registerExtenderCallbacks(self, callbacks):
    print 'SQLiPy - %s\nBurp interface to SQLMap via the SQLMap API\nOriginal by Josh Berry (github.com/codewatchorg/sqlipy), 0.9.0 by Tr0j4n1 (github.com/Tr0j4n1/sqlipy)\n\n' % VERSION
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName('SQLiPy Sqlmap Integration')
    callbacks.registerExtensionStateListener(self)
    callbacks.registerContextMenuFactory(self)

    self.opener = urllib2.build_opener(urllib2.ProxyHandler({}))
    self.lock = threading.RLock()
    self.apiLock = threading.Lock()
    self.tasks = []
    self.selected = None
    self.apiHost = self.setting('host', '127.0.0.1')
    self.apiPort = self.setting('port', '9090')
    self.apiProcess = None
    self.apiState = 'stopped'
    self.polling = True
    self.message = None
    self.messageUrl = None
    self.bold = []
    self.mono = []
    self.primary = []
    self.dumpKeys = []

    self.root = swing.JTabbedPane()
    self.root.addTab('Scan', self.buildScanTab())
    self.root.addTab('Tasks', self.buildTasksTab())
    self.root.addTab('API', self.buildApiTab())
    self.setApiState('stopped', 'sqlmap API is not running')
    self.showTask(None)

    callbacks.customizeUiComponent(self.root)
    self.polish()
    callbacks.addSuiteTab(self)

    inBackground(self.startup)
    inBackground(self.pollLoop)
    return

  def getTabCaption(self):
    return 'SQLiPy'

  def getUiComponent(self):
    return self.root

  # Create a menu item for any selected request
  def createMenuItems(self, invocation):
    try:
      messages = invocation.getSelectedMessages()
      if not messages or messages[0].getRequest() is None:
        return None
    except:
      return None
    return [swing.JMenuItem('SQLiPy Scan', actionPerformed=lambda e, inv=invocation: self.sqlMapScan(inv))]

  # ---------- Settings ----------

  def setting(self, key, default):
    try:
      value = self._callbacks.loadExtensionSetting('sqlipy.' + key)
      return value if value else default
    except:
      return default

  def saveSetting(self, key, value):
    try:
      self._callbacks.saveExtensionSetting('sqlipy.' + key, value)
    except:
      pass

  # ---------- UI ----------

  def textArea(self, rows, mono=False):
    area = swing.JTextArea(rows, 20)
    area.setLineWrap(True)
    area.setWrapStyleWord(not mono)
    if mono:
      self.mono.append(area)
    return area

  def scroll(self, comp):
    pane = swing.JScrollPane(comp)
    pane.setPreferredSize(Dimension(100, comp.getPreferredSize().height + 6))
    pane.setMinimumSize(Dimension(60, comp.getPreferredSize().height + 6))
    return pane

  def title(self, text):
    label = swing.JLabel(text)
    self.bold.append(label)
    return label

  def statusLabel(self):
    label = swing.JLabel(' ')
    label.setMinimumSize(Dimension(0, 0))
    label.setIconTextGap(8)
    return label

  def primaryButton(self, text, handler):
    button = swing.JButton(text, actionPerformed=handler)
    self.primary.append(button)
    return button

  def page(self, form):
    form.finish()
    page = ScrollPage()
    page.setLayout(CappedWidthLayout(1060))
    page.setBorder(EmptyBorder(12, 16, 16, 16))
    page.add(form.panel)
    pane = swing.JScrollPane(page)
    pane.setBorder(None)
    pane.getVerticalScrollBar().setUnitIncrement(16)
    return pane

  def polish(self):
    # Burp restyles the tree in customizeUiComponent, so apply our font tweaks afterwards
    for c in self.bold:
      c.setFont(c.getFont().deriveFont(Font.BOLD))
    size = self.root.getFont().getSize()
    for c in self.mono:
      c.setFont(Font(Font.MONOSPACED, Font.PLAIN, size))
    style = PrimaryStyle()
    for b in self.primary:
      b.setFont(b.getFont().deriveFont(Font.BOLD))
      style.apply(b)
      b.addPropertyChangeListener('enabled', style)

  def buildScanTab(self):
    f = Form()

    self.scanStatus = self.statusLabel()
    self.scanStartApi = swing.JButton('Start API', actionPerformed=self.startApi)
    f.full(hbox((self.scanStatus, 1.0), self.scanStartApi), bottom=6)

    f.full(swing.JSeparator(), top=4, bottom=2)
    f.full(self.title('Target'), top=4, bottom=4)
    self.fURL = swing.JTextField(30)
    f.row('URL', self.fURL)
    self.cMethod = swing.JComboBox(['Default', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    self.fParam = swing.JTextField(12)
    f.row('Method', hbox(self.cMethod, 'Parameter(s) to test', (self.fParam, 1.0)))
    self.tData = self.textArea(3, mono=True)
    f.row('POST data', self.scroll(self.tData), tall=True)
    self.fCookie = swing.JTextField(30)
    f.row('Cookie', self.fCookie)

    acc = Accordion(self.bold, f)

    s = acc.section('What to get')
    self.chk = OrderedDict()
    grid = swing.JPanel(GridLayout(0, 4, 24, 0))
    grid.setOpaque(False)
    for key, text in ENUM_OPTIONS:
      self.chk[key] = swing.JCheckBox(text)
      grid.add(self.chk[key])
    s.add(f.row('Enumerate', grid, tall=True, stretch=False))
    self.chkDump = swing.JCheckBox('Dump rows')
    self.chkDumpAll = swing.JCheckBox('Dump all databases')
    self.chkSkipSys = swing.JCheckBox('Skip system databases', True)
    s.add(f.row('Dump', hbox(self.chkDump, self.chkDumpAll, self.chkSkipSys)))
    self.fDb = swing.JTextField(8)
    self.fTbl = swing.JTextField(8)
    self.fCol = swing.JTextField(8)
    s.add(f.row('Database', hbox((self.fDb, 1.0), 'Table(s)', (self.fTbl, 1.0), 'Column(s)', (self.fCol, 1.0))))
    self.fWhere = swing.JTextField(8)
    self.fStart = swing.JTextField(4)
    self.fStop = swing.JTextField(4)
    s.add(f.row('Where', hbox((self.fWhere, 1.0), 'Rows from', self.fStart, 'to', self.fStop)))
    s.add(f.full(swing.JLabel('Leave Database empty to use the current database. Separate several tables or columns with commas.'), top=2, bottom=6))
    whatToGet = s

    s = acc.section('Detection')
    self.cLevel = swing.JComboBox([1, 2, 3, 4, 5])
    self.cLevel.setSelectedIndex(2)
    self.cRisk = swing.JComboBox([1, 2, 3])
    self.cRisk.setSelectedIndex(0)
    self.fTech = swing.JTextField('BEUSTQ', 7)
    s.add(f.row('Level', hbox(self.cLevel, 'Risk', self.cRisk, 'Technique', self.fTech)))
    self.cDbms = swing.JComboBox(DBMS_VALUES)
    self.cOs = swing.JComboBox(['Any', 'Linux', 'Windows'])
    s.add(f.row('DBMS', hbox(self.cDbms, 'OS', self.cOs)))
    self.fTamper = swing.JTextField(20)
    s.add(f.row('Tamper scripts', self.fTamper))
    self.chkText = swing.JCheckBox('Text only')
    self.chkHpp = swing.JCheckBox('HTTP parameter pollution')
    s.add(f.row('', hbox(self.chkText, self.chkHpp)))

    s = acc.section('Request')
    self.fUA = swing.JTextField(30)
    s.add(f.row('User-Agent', self.fUA))
    self.fReferer = swing.JTextField(30)
    s.add(f.row('Referer', self.fReferer))
    self.tHeaders = self.textArea(4, mono=True)
    s.add(f.row('Extra headers', self.scroll(self.tHeaders), tall=True))
    self.fIgnore = swing.JTextField(6)
    self.fProxy = swing.JTextField(16)
    s.add(f.row('Ignore code', hbox(self.fIgnore, 'Proxy', (self.fProxy, 1.0))))
    self.cAuth = swing.JComboBox(['None', 'Basic', 'Digest', 'Bearer', 'NTLM'])
    self.fAuthUser = swing.JTextField(10)
    self.fAuthPass = swing.JPasswordField(10)
    s.add(f.row('Auth', hbox(self.cAuth, 'User', (self.fAuthUser, 1.0), 'Password / token', (self.fAuthPass, 1.0))))
    self.chkTor = swing.JCheckBox('Use Tor')
    self.cTorType = swing.JComboBox(['HTTP', 'SOCKS4', 'SOCKS5'])
    self.cTorType.setSelectedIndex(2)
    self.fTorPort = swing.JTextField('9050', 5)
    s.add(f.row('Tor', hbox(self.chkTor, 'Type', self.cTorType, 'Port', self.fTorPort)))

    s = acc.section('Speed and log')
    self.speed, rows = speedRows(f)
    s.add(rows)

    acc.toggle(whatToGet)

    f.full(swing.JSeparator(), top=12, bottom=6)
    self.bScan = self.primaryButton('Start scan', self.startScan)
    self.scanMsg = self.statusLabel()
    f.full(hbox(self.bScan, (self.scanMsg, 1.0)))
    return self.page(f)

  def buildTasksTab(self):
    self.taskModel = ReadOnlyModel(['ID', 'Job', 'Target', 'Status', 'Started'], 0)
    self.taskTable = swing.JTable(self.taskModel)
    self.taskTable.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)
    self.taskTable.setFillsViewportHeight(True)
    columns = self.taskTable.getColumnModel()
    for i, width in enumerate([90, 190, 520, 130, 80]):
      columns.getColumn(i).setPreferredWidth(width)
    columns.getColumn(3).setCellRenderer(StatusRenderer())
    self.taskTable.getSelectionModel().addListSelectionListener(Selection(self.onTaskSelected))
    top = swing.JScrollPane(self.taskTable)
    top.setMinimumSize(Dimension(100, 80))

    self.taskTitle = self.statusLabel()
    self.bDump = self.primaryButton('Dump...', self.dumpDialog)
    self.bStop = swing.JButton('Stop', actionPerformed=self.stopTask)
    self.bRemove = swing.JButton('Remove', actionPerformed=self.removeTask)
    head = hbox((self.taskTitle, 1.0), self.bDump, self.bStop, self.bRemove)
    head.setBorder(EmptyBorder(8, 10, 8, 10))

    self.resultsPane = swing.JEditorPane()
    self.resultsPane.setContentType('text/html')
    self.resultsPane.setEditable(False)
    self.resultsPane.putClientProperty(swing.JEditorPane.HONOR_DISPLAY_PROPERTIES, True)

    self.dumpListModel = swing.DefaultListModel()
    self.dumpList = swing.JList(self.dumpListModel)
    self.dumpList.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)
    self.dumpList.addListSelectionListener(Selection(self.showDump))
    self.dumpTable = swing.JTable(ReadOnlyModel(0, 0))
    self.dumpTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_OFF)
    # Select single cells, so Ctrl+C copies just what is selected
    self.dumpTable.setCellSelectionEnabled(True)
    self.dumpTable.addMouseListener(CopyMenu(self))
    self.dumpInfo = ''
    self.dumpTitle = self.statusLabel()
    self.bSaveCsv = swing.JButton('Save CSV...', actionPerformed=self.saveDump)
    dumpHead = hbox((self.dumpTitle, 1.0), self.bSaveCsv)
    dumpHead.setBorder(EmptyBorder(6, 8, 6, 8))
    right = swing.JPanel(BorderLayout())
    right.add(dumpHead, BorderLayout.NORTH)
    right.add(swing.JScrollPane(self.dumpTable), BorderLayout.CENTER)
    listPane = swing.JScrollPane(self.dumpList)
    listPane.setMinimumSize(Dimension(120, 50))
    dumps = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT, listPane, right)
    dumps.setDividerLocation(220)
    dumps.setBorder(None)

    self.logArea = self.textArea(10, mono=True)
    self.logArea.setEditable(False)
    self.cmdArea = self.textArea(4, mono=True)
    self.cmdArea.setEditable(False)

    self.detailTabs = swing.JTabbedPane()
    self.detailTabs.addTab('Results', swing.JScrollPane(self.resultsPane))
    self.detailTabs.addTab('Dumped data', dumps)
    self.detailTabs.addTab('Log', swing.JScrollPane(self.logArea))
    self.detailTabs.addTab('sqlmap command', swing.JScrollPane(self.cmdArea))

    detail = swing.JPanel(BorderLayout())
    detail.add(head, BorderLayout.NORTH)
    detail.add(self.detailTabs, BorderLayout.CENTER)

    split = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, top, detail)
    split.setResizeWeight(0.3)
    split.setDividerLocation(190)
    split.setBorder(None)
    return split

  def buildApiTab(self):
    f = Form()

    self.apiStatus = self.statusLabel()
    f.full(self.apiStatus, bottom=6)
    f.full(swing.JSeparator(), top=4, bottom=2)

    f.full(self.title('Run the sqlmap API from Burp'), top=4, bottom=4)
    self.fPython = swing.JTextField(self.setting('python', ''), 30)
    f.row('Python', hbox((self.fPython, 1.0), swing.JButton('Browse...', actionPerformed=self.setPython)))
    self.fApiFile = swing.JTextField(self.setting('apifile', ''), 30)
    f.row('sqlmapapi.py', hbox((self.fApiFile, 1.0), swing.JButton('Browse...', actionPerformed=self.setAPI)))
    self.fHost = swing.JTextField(self.apiHost, 12)
    self.fPort = swing.JTextField(self.apiPort, 6)
    f.row('Listen on', hbox(self.fHost, 'Port', self.fPort))
    self.bStartApi = self.primaryButton('Start API', self.startApi)
    self.bStopApi = swing.JButton('Stop API', actionPerformed=self.stopAPI)
    f.row('', hbox(self.bStartApi, self.bStopApi))
    f.full(swing.JLabel('Already running sqlmapapi.py yourself? Enter its host and port, then press Start API to connect to it.'), top=6)

    f.full(swing.JSeparator(), top=14, bottom=2)
    f.full(self.title('API output'), top=4, bottom=4)
    self.apiOutput = self.textArea(14, mono=True)
    self.apiOutput.setEditable(False)
    f.full(self.scroll(self.apiOutput))
    return self.page(f)

  # ---------- Context menu ----------

  def sqlMapScan(self, invocation):
    try:
      message = invocation.getSelectedMessages()[0]
      reqInfo = self._helpers.analyzeRequest(message)
      reqBody = message.getRequest()
      bodyData = self._helpers.bytesToString(reqBody[reqInfo.getBodyOffset():])
      skip = ('host', 'content-length', 'connection', 'keep-alive', 'proxy-connection', 'accept-encoding', 'if-none-match', 'if-modified-since')
      referer = ''
      ua = ''
      cookie = ''
      extra = []

      for header in list(reqInfo.getHeaders())[1:]:
        if ':' not in header or header.startswith(':'):
          continue
        name, value = header.split(':', 1)
        lname = name.strip().lower()
        if lname == 'referer':
          referer = value.strip()
        elif lname == 'user-agent':
          ua = value.strip()
        elif lname == 'cookie':
          cookie = value.strip()
        elif lname not in skip:
          extra.append(header)

      method = reqInfo.getMethod()
      self.cMethod.setSelectedItem(method if method in ('PUT', 'DELETE', 'PATCH') else 'Default')
      self.fURL.setText(str(reqInfo.getUrl()))
      self.tData.setText(bodyData)
      self.fCookie.setText(cookie)
      self.fUA.setText(ua)
      self.fReferer.setText(referer)
      self.tHeaders.setText('\n'.join(extra))
      self.message = message
      self.messageUrl = reqInfo.getUrl()
      self.scanMsg.setText('Request loaded. Pick what to get, then press Start scan.')
      self.root.setSelectedIndex(0)
      parent = self.root.getParent()
      if isinstance(parent, swing.JTabbedPane):
        parent.setSelectedComponent(self.root)
    except:
      print 'Failed to add data to scan tab.\n' + traceback.format_exc()

  # ---------- sqlmap API ----------

  def api(self, path, payload=None, timeout=10):
    req = urllib2.Request('http://%s:%s%s' % (self.apiHost, self.apiPort, path))
    body = None
    if payload is not None:
      body = json.dumps(payload)
      req.add_header('Content-Type', 'application/json')
    resp = self.opener.open(req, body, timeout)
    try:
      return json.loads(resp.read(), object_pairs_hook=OrderedDict)
    finally:
      resp.close()

  def apiVersion(self):
    try:
      resp = self.api('/version', timeout=3)
      return resp.get('version') if resp.get('success') else None
    except:
      return None

  def apiConfig(self):
    return {'python': self.fPython.getText().strip(), 'apifile': self.fApiFile.getText().strip(),
            'host': self.fHost.getText().strip() or '127.0.0.1', 'port': self.fPort.getText().strip() or '9090'}

  def setApiState(self, state, text):
    self.apiState = state
    color = {'running': GREEN, 'starting': AMBER, 'failed': RED}.get(state, GREY)
    for label in (self.apiStatus, self.scanStatus):
      label.setIcon(Dot(color))
      label.setText(text)
    self.scanStartApi.setVisible(state in ('stopped', 'failed'))
    self.bStartApi.setEnabled(state in ('stopped', 'failed'))
    self.bStopApi.setEnabled(state == 'running')

  def appendApiOutput(self, line):
    self.apiOutput.append(line + '\n')
    doc = self.apiOutput.getDocument()
    if doc.getLength() > 200000:
      doc.remove(0, doc.getLength() - 150000)
    self.apiOutput.setCaretPosition(doc.getLength())

  def setPython(self, e):
    chooser = swing.JFileChooser()
    if chooser.showOpenDialog(self.root) == swing.JFileChooser.APPROVE_OPTION:
      path = chooser.getSelectedFile().getPath()
      self.fPython.setText(path)
      self.saveSetting('python', path)
      print 'Selected Python at ' + path

  def setAPI(self, e):
    chooser = swing.JFileChooser()
    chooser.addChoosableFileFilter(FileNameExtensionFilter('python files', ['py']))
    if chooser.showOpenDialog(self.root) == swing.JFileChooser.APPROVE_OPTION:
      path = chooser.getSelectedFile().getPath()
      self.fApiFile.setText(path)
      self.saveSetting('apifile', path)
      print 'Selected API at ' + path

  def startup(self):
    # Find Python and sqlmapapi.py, then connect if an API is already listening. Runs in the background.
    python = self.setting('python', '')
    if not python:
      python, version = self.findPython()
      if python:
        print 'Python %s found at: %s\n' % (version, python)
        onEdt(self.fPython.setText, python)
      else:
        print 'Could not find Python 2.7 or 3. Set it on the API tab.\n'

    apifile = self.setting('apifile', '')
    if not apifile or not os.path.isfile(apifile):
      apifile = self.findSqlmapApi()
      if apifile:
        print 'SQLMap API found at: ' + apifile + '\n'
        onEdt(self.fApiFile.setText, apifile)
      else:
        print 'Could not find SQLMap API file.\n'

    version = self.apiVersion()
    if version and self.apiState == 'stopped':
      onEdt(self.setApiState, 'running', 'Connected to sqlmap API %s on %s:%s' % (version, self.apiHost, self.apiPort))

  def pythonVersion(self, exe):
    try:
      out = subprocess.check_output([exe, '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'], stderr=subprocess.STDOUT)
      m = re.search(r'(\d+)\.(\d+)', out)
      if m and (m.group(1) == '3' or m.group(0) == '2.7'):
        return m.group(0)
    except:
      pass
    return None

  def findPython(self):
    candidates = []
    if IS_WINDOWS:
      for name in ('python', 'python3', 'py'):
        try:
          out = subprocess.check_output(['where', name], stderr=subprocess.STDOUT)
          candidates += [l.strip() for l in out.splitlines() if l.strip().lower().endswith('.exe')]
        except:
          pass
    else:
      for name in ('python3', 'python', 'python2.7'):
        try:
          out = subprocess.check_output(['which', name], stderr=subprocess.STDOUT)
          candidates += [l.strip() for l in out.splitlines() if l.strip()]
        except:
          pass
    for exe in candidates:
      version = self.pythonVersion(exe)
      if version:
        return exe, version
    return None, None

  def findSqlmapApi(self):
    base = os.getcwd()

    # The BApp ships sqlmap as a zip; extract it the first time the extension runs
    if os.path.isfile(os.path.join(base, 'sqlmap.zip')):
      try:
        with zipfile.ZipFile(os.path.join(base, 'sqlmap.zip')) as sqlmapzip:
          sqlmapzip.extractall(base)
        os.remove(os.path.join(base, 'sqlmap.zip'))
      except:
        print 'Failed to extract sqlmap.zip\n'

    candidates = [os.path.join(base, 'sqlmap', 'sqlmapapi.py')]
    try:
      candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sqlmap', 'sqlmapapi.py'))
    except NameError:
      pass
    if os.environ.get('APPDATA'):
      candidates.append(os.path.join(os.environ['APPDATA'], 'BurpSuite', 'bapps', BAPP_UUID, 'sqlmap', 'sqlmapapi.py'))
    candidates.append(os.path.join(os.path.expanduser('~'), '.BurpSuite', 'bapps', BAPP_UUID, 'sqlmap', 'sqlmapapi.py'))

    for path in candidates:
      if os.path.isfile(path):
        return path
    return None

  def startApi(self, e=None):
    cfg = self.apiConfig()
    for key in ('python', 'apifile', 'host', 'port'):
      self.saveSetting(key, cfg[key])
    inBackground(self.ensureApi, cfg)

  def ensureApi(self, cfg):
    # Connect to an API on host:port, or start one. Returns True when the API answers. Runs in the background.
    with self.apiLock:
      if self.apiState == 'running' and (cfg['host'], cfg['port']) == (self.apiHost, self.apiPort) and self.apiVersion():
        return True

      self.apiHost, self.apiPort = cfg['host'], cfg['port']
      onEdt(self.setApiState, 'starting', 'Starting sqlmap API on %s:%s...' % (self.apiHost, self.apiPort))

      version = self.apiVersion()
      if version:
        onEdt(self.setApiState, 'running', 'Connected to sqlmap API %s on %s:%s' % (version, self.apiHost, self.apiPort))
        return True

      if not cfg['python']:
        onEdt(self.setApiState, 'failed', 'Could not start the sqlmap API: set the Python path on the API tab')
        return False
      if not cfg['apifile'] or not os.path.isfile(cfg['apifile']):
        onEdt(self.setApiState, 'failed', 'Could not start the sqlmap API: set the sqlmapapi.py path on the API tab')
        return False

      cmd = [cfg['python'], cfg['apifile'], '-s', '-H', self.apiHost, '-p', self.apiPort]
      print 'Calling: ' + ' '.join(cmd) + '\n'
      onEdt(self.appendApiOutput, '> ' + ' '.join(cmd))
      try:
        builder = ProcessBuilder(cmd)
        builder.directory(File(os.path.dirname(cfg['apifile'])))
        builder.redirectErrorStream(True)
        process = builder.start()
      except:
        onEdt(self.setApiState, 'failed', 'Could not start the sqlmap API: ' + errorText())
        return False

      self.apiProcess = process
      inBackground(self.readApiOutput, process)

      for i in range(60):
        time.sleep(0.5)
        if not process.isAlive():
          self.apiProcess = None
          onEdt(self.setApiState, 'failed', 'The sqlmap API exited with code %d. Read the API tab output.' % process.exitValue())
          return False
        version = self.apiVersion()
        if version:
          print 'SQLMap API started.\n'
          onEdt(self.setApiState, 'running', 'sqlmap API %s running on %s:%s' % (version, self.apiHost, self.apiPort))
          return True

      self.apiProcess = None
      self.killProcess(process)
      onEdt(self.setApiState, 'failed', 'The sqlmap API did not answer within 30 seconds. Read the API tab output.')
      return False

  def readApiOutput(self, process):
    reader = BufferedReader(InputStreamReader(process.getInputStream()))
    while True:
      line = reader.readLine()
      if line is None:
        break
      onEdt(self.appendApiOutput, line)

  def killProcess(self, process):
    try:
      for child in process.descendants().toArray():
        child.destroy()
    except:
      pass
    process.destroy()

  def stopAPI(self, e=None):
    inBackground(self.shutdown, True)

  def shutdown(self, updateUi):
    # Kill running scans, then the API process if Burp started it
    for t in list(self.tasks):
      if t.status == 'Running':
        try:
          self.api('/scan/%s/kill' % t.id, timeout=3)
          print 'Scan stopped for ID: ' + t.id + '\n'
        except:
          print 'Failed to stop scan on ID: ' + t.id + ', likely already completed\n'
        t.status = 'Stopped'
        if updateUi:
          onEdt(self.taskChanged, t)

    process, self.apiProcess = self.apiProcess, None
    if process is not None:
      self.killProcess(process)
      print 'Stopping the SQLMap API\n'

    if updateUi:
      text = 'sqlmap API stopped' if process is not None else 'Disconnected from the sqlmap API on %s:%s' % (self.apiHost, self.apiPort)
      onEdt(self.setApiState, 'stopped', text)

  def extensionUnloaded(self):
    self.polling = False
    self.shutdown(False)

  # ---------- Scans ----------

  def scanOptions(self):
    text = lambda field: field.getText().strip()
    o = OrderedDict()
    o['url'] = text(self.fURL)

    if self.cMethod.getSelectedItem() != 'Default':
      o['method'] = self.cMethod.getSelectedItem()
    if self.tData.getText().strip():
      o['data'] = self.tData.getText().strip('\r\n')
    if text(self.fCookie):
      o['cookie'] = text(self.fCookie)
    if text(self.fUA):
      o['agent'] = text(self.fUA)
    if text(self.fReferer):
      o['referer'] = text(self.fReferer)

    headers = [h.strip() for h in self.tHeaders.getText().splitlines() if ':' in h]
    if headers:
      o['headers'] = '\n'.join(headers)

    auth = self.cAuth.getSelectedItem()
    password = unicode(String(self.fAuthPass.getPassword()))
    if auth != 'None':
      o['authType'] = auth
      o['authCred'] = (password or text(self.fAuthUser)) if auth == 'Bearer' else text(self.fAuthUser) + ':' + password

    if text(self.fIgnore):
      o['ignoreCode'] = text(self.fIgnore)
    if text(self.fProxy):
      o['proxy'] = text(self.fProxy) if '://' in text(self.fProxy) else 'http://' + text(self.fProxy)
    if self.chkTor.isSelected():
      o['tor'] = True
      o['torType'] = self.cTorType.getSelectedItem()
      if text(self.fTorPort).isdigit():
        o['torPort'] = int(text(self.fTorPort))

    if text(self.fParam):
      o['testParameter'] = text(self.fParam)
    if self.cDbms.getSelectedItem() != 'Any':
      o['dbms'] = self.cDbms.getSelectedItem()
    if self.cOs.getSelectedItem() != 'Any':
      o['os'] = self.cOs.getSelectedItem()
    if text(self.fTamper):
      o['tamper'] = text(self.fTamper)
    o['level'] = self.cLevel.getSelectedItem()
    o['risk'] = self.cRisk.getSelectedItem()
    if text(self.fTech):
      o['technique'] = text(self.fTech)
    if self.chkText.isSelected():
      o['textOnly'] = True
    if self.chkHpp.isSelected():
      o['hpp'] = True

    for key, box in self.speed.items():
      o[key] = box.getSelectedItem()

    o['getBanner'] = True
    for key, box in self.chk.items():
      if box.isSelected():
        o[key] = True

    if self.chkDumpAll.isSelected():
      o['dumpAll'] = True
    elif self.chkDump.isSelected():
      o['dumpTable'] = True

    listsTables = any([o.get(k) for k in ('getTables', 'getColumns', 'getSchema', 'getCount', 'dumpTable', 'dumpAll')])
    if listsTables and self.chkSkipSys.isSelected():
      o['excludeSysDbs'] = True
    for key, field in (('db', self.fDb), ('tbl', self.fTbl), ('col', self.fCol), ('dumpWhere', self.fWhere)):
      if text(field):
        o[key] = text(field)
    for key, field in (('limitStart', self.fStart), ('limitStop', self.fStop)):
      if text(field).isdigit():
        o[key] = int(text(field))

    o['answers'] = ANSWERS
    return o

  def startScan(self, e=None):
    url = self.fURL.getText().strip()
    if not url:
      self.scanMsg.setText('Enter a URL, or right-click a request in Burp and choose SQLiPy Scan.')
      return

    message, messageUrl = self.message, self.messageUrl
    if messageUrl is None or url.split('?')[0] != str(messageUrl).split('?')[0]:
      message, messageUrl = None, None

    self.bScan.setEnabled(False)
    self.scanMsg.setText('Starting scan...')
    inBackground(self.submit, 'Scan', url, self.scanOptions(), message, messageUrl, None, self.apiConfig())

  def submit(self, job, url, opts, message, messageUrl, parent, cfg):
    # Create a sqlmap task, set its options and start it. Runs in the background.
    try:
      if not self.ensureApi(cfg):
        onEdt(self.submitDone, None, 'The sqlmap API is not running. See the status at the top.')
        return

      resp = self.api('/task/new')
      if not resp.get('success'):
        raise Exception('task creation failed')
      taskid = str(resp['taskid'])
      print 'Created SQLMap Task: ' + taskid + '\n'

      resp = self.api('/option/%s/set' % taskid, opts)
      if not resp.get('success'):
        raise Exception('could not set options: ' + unicode(resp.get('message')))
      print 'SQLMap options set on Task ' + taskid + ': ' + json.dumps(opts) + '\n'

      resp = self.api('/scan/%s/start' % taskid, {'url': url})
      if not resp.get('success'):
        raise Exception('could not start the scan: ' + unicode(resp.get('message')))

      task = ScanTask(taskid, job, url, opts, message, messageUrl, parent)
      say('SQLMap Command: ' + task.cmd + '\n')
      say('Started SQLMap Scan on Task ' + taskid + ' with Engine ID: ' + str(resp.get('engineid')) + ' - ' + url + '\n')
      onEdt(self.submitDone, task, None)
    except:
      say(traceback.format_exc())
      onEdt(self.submitDone, None, 'SQLMap task creation failed: ' + errorText())

  def submitDone(self, task, error):
    self.bScan.setEnabled(True)
    if error:
      self.scanMsg.setText(error)
      if self.selected is not None:
        self.showTask(self.selected)
      return

    # Rows in taskModel and self.tasks share one order, so both change here on the Swing thread
    with self.lock:
      self.tasks.append(task)
    self.scanMsg.setText('Started task %s. Follow it on the Tasks tab.' % task.id[:8])
    self.taskModel.addRow([task.id[:8], task.job, task.url, task.status, task.started])
    row = self.taskModel.getRowCount() - 1
    self.taskTable.setRowSelectionInterval(row, row)
    self.root.setSelectedIndex(1)

  def pollLoop(self):
    while self.polling:
      time.sleep(2)
      guarded(self.pollOnce)

  def pollOnce(self):
    process = self.apiProcess
    if process is not None and not process.isAlive():
      self.apiProcess = None
      onEdt(self.setApiState, 'failed', 'The sqlmap API exited with code %d. Read the API tab output.' % process.exitValue())
    for t in [t for t in list(self.tasks) if t.status == 'Running']:
      guarded(self.pollTask, t)

  def pollTask(self, t):
    resp = self.api('/scan/%s/status' % t.id, timeout=5)
    if not resp.get('success'):
      t.status = 'Failed'
      t.log.append({'time': time.strftime('%H:%M:%S'), 'level': 'ERROR', 'message': 'The sqlmap API no longer knows this task (was the API restarted?)'})
      onEdt(self.taskChanged, t)
      return

    if resp.get('status') == 'terminated':
      self.collect(t, True)
      if t.result.vulnerable or t.result.dumps:
        t.status = 'Vulnerable' if t.job == 'Scan' else 'Done'
      elif t.job != 'Scan' and resp.get('returncode') == 0:
        t.status = 'Done'
      elif resp.get('returncode') not in (0, None):
        t.status = 'Failed'
      else:
        t.status = 'Not vulnerable'
      print 'Scan for task %s finished: %s\n' % (t.id, t.status)
      self.report(t)
      onEdt(self.taskChanged, t)
    elif t is self.selected:
      # Show progress for the task the user is looking at
      self.collect(t, False)
      onEdt(self.taskChanged, t)

  def collect(self, t, final):
    data = self.api('/scan/%s/data' % t.id)
    log = self.api('/scan/%s/log' % t.id)
    t.log = log.get('log') or []
    result = parseResults(data.get('data'), data.get('error'))
    if final:
      for key, table in self.csvDumps(t).items():
        if key not in result.dumps or len(table[1]) > len(result.dumps[key][1]):
          result.dumps[key] = table
    t.result = result

  def csvDumps(self, t):
    # The API keeps only the last dumped table, so read every CSV file the log says sqlmap wrote
    found = OrderedDict()
    for entry in t.log:
      m = CSV_LOG.search(entry.get('message') or '')
      if not m:
        continue
      label, path = m.group(1), m.group(2)
      raw = None
      try:
        if os.path.isfile(path):
          with open(path, 'rb') as fh:
            raw = fh.read()
        else:
          parts = re.split(r'[\\/]', path)
          if 'dump' in parts[1:]:
            i = len(parts) - 1 - parts[::-1].index('dump')
            quote = lambda p: urllib.quote(p.encode('utf-8'), safe='')
            resp = self.api('/download/%s/%s/%s' % (t.id, quote(parts[i - 1]), '/'.join([quote(p) for p in parts[i:]])))
            if resp.get('success'):
              raw = base64.b64decode(resp['file'])
      except:
        say(u'Could not read dump file %s: %s\n' % (path, errorText()))
      if raw:
        table = parseCsv(raw)
        if table:
          found[label] = table
    return found

  def report(self, t):
    if t.reported or t.job != 'Scan' or not t.result.vulnerable or t.message is None:
      return
    t.reported = True
    try:
      if not re.search('Professional|Enterprise', self._callbacks.getBurpVersion()[0]):
        print 'Burp Community cannot add scanner issues. SQLi results for task %s are on the SQLiPy Tasks tab.\n' % t.id
        return
      issue = SqlMapScanIssue(t.message.getHttpService(), t.messageUrl, [t.message], 'SQLMap Scan Finding',
                              issueHtml(t.result), 'Certain', 'High')
      self._callbacks.addScanIssue(issue)
      print 'SQLi vulnerabilities were found for task ' + t.id + ' and have been reported.\n'
    except:
      say(u'Could not add the Burp issue for task %s: %s\n' % (t.id, errorText()))

  # ---------- Tasks tab ----------

  def rowOf(self, t):
    with self.lock:
      return self.tasks.index(t) if t in self.tasks else -1

  def taskChanged(self, t):
    row = self.rowOf(t)
    if row >= 0:
      self.taskModel.setValueAt(t.status, row, 3)
    if t is self.selected:
      self.showTask(t)

  def onTaskSelected(self):
    row = self.taskTable.getSelectedRow()
    with self.lock:
      self.selected = self.tasks[row] if 0 <= row < len(self.tasks) else None
    self.showTask(self.selected, True)

  def showTask(self, t, reset=False):
    if t is None:
      self.taskTitle.setIcon(None)
      self.taskTitle.setText('No task selected. Right-click a request in Burp and choose SQLiPy Scan.')
      for b in (self.bDump, self.bStop, self.bRemove):
        b.setEnabled(False)
      self.resultsPane.setText('')
      self.logArea.setText('')
      self.cmdArea.setText('')
      self.fillDumps(None)
      return

    self.taskTitle.setIcon(Dot(STATUS_COLORS.get(t.status, GREY)))
    self.taskTitle.setText(u'%s  \u00b7  %s  \u00b7  %s' % (t.job, t.status, t.url))
    self.bDump.setEnabled(bool(t.result and t.result.vulnerable))
    self.bStop.setEnabled(t.status == 'Running')
    self.bRemove.setEnabled(True)

    html = resultsHtml(t)
    if reset or html != getattr(self, 'shownHtml', None):
      self.shownHtml = html
      self.resultsPane.setText(html)
      self.resultsPane.setCaretPosition(0)

    log = '\n'.join(['%s  %-8s %s' % (l.get('time'), l.get('level'), l.get('message')) for l in t.log])
    if log != self.logArea.getText():
      self.logArea.setText(log)
      self.logArea.setCaretPosition(len(log))
    self.cmdArea.setText(t.cmd)

    keys = list(t.result.dumps.keys()) if t.result else []
    if reset or keys != self.dumpKeys:
      self.fillDumps(t)
      if keys and t.status != 'Running' and t.job != 'Scan':
        self.detailTabs.setSelectedIndex(1)

  def fillDumps(self, t):
    self.dumpKeys = list(t.result.dumps.keys()) if t and t.result else []
    self.dumpListModel.clear()
    for key in self.dumpKeys:
      self.dumpListModel.addElement(u'%s  (%d rows)' % (key, len(t.result.dumps[key][1])))
    self.detailTabs.setTitleAt(1, 'Dumped data (%d)' % len(self.dumpKeys) if self.dumpKeys else 'Dumped data')
    if self.dumpKeys:
      self.dumpList.setSelectedIndex(0)
    else:
      self.dumpTable.setModel(ReadOnlyModel(0, 0))
      self.dumpTitle.setText('No rows dumped in this task. Select a vulnerable task and press Dump...')
      self.bSaveCsv.setEnabled(False)

  def selectedDump(self):
    i = self.dumpList.getSelectedIndex()
    if self.selected is None or self.selected.result is None or not (0 <= i < len(self.dumpKeys)):
      return None, None
    key = self.dumpKeys[i]
    return key, self.selected.result.dumps.get(key)

  def showDump(self):
    key, table = self.selectedDump()
    if table is None:
      return
    cols, rows = table
    model = ReadOnlyModel(cols, 0)
    for r in rows:
      model.addRow([('NULL' if v is None else v) for v in r])
    self.dumpTable.setModel(model)
    # Few columns fill the view; many columns keep a readable width and scroll sideways
    self.dumpTable.setAutoResizeMode(swing.JTable.AUTO_RESIZE_OFF if len(cols) > 6 else swing.JTable.AUTO_RESIZE_ALL_COLUMNS)
    for i in range(len(cols)):
      self.dumpTable.getColumnModel().getColumn(i).setPreferredWidth(160)
    self.dumpInfo = u'%s  \u00b7  %d rows  \u00b7  %d columns' % (key, len(rows), len(cols))
    self.dumpTitle.setText(self.dumpInfo + u'  \u00b7  right-click a cell to copy')
    self.bSaveCsv.setEnabled(True)

  def clipboard(self):
    return Toolkit.getDefaultToolkit().getSystemClipboard()

  def copyDump(self, what, row, col):
    # Copies in the order shown on screen: tabs between columns, new lines between rows
    table = self.dumpTable
    cell = lambda r, c: unicode(table.getValueAt(r, c))
    rows, cols = range(table.getRowCount()), range(table.getColumnCount())
    if what == 'cell':
      text = cell(row, col)
    elif what == 'row':
      text = '\t'.join([cell(row, c) for c in cols])
    elif what == 'column':
      text = '\n'.join([cell(r, col) for r in rows])
    else:
      header = '\t'.join([unicode(table.getColumnName(c)) for c in cols])
      text = '\n'.join([header] + ['\t'.join([cell(r, c) for c in cols]) for r in rows])
    self.clipboard().setContents(StringSelection(text), None)
    self.dumpTitle.setText(self.dumpInfo + u'  \u00b7  copied ' + what)

  def saveDump(self, e=None):
    key, table = self.selectedDump()
    if table is None:
      return
    chooser = swing.JFileChooser()
    chooser.setSelectedFile(File(re.sub(r'[^\w.-]', '_', key) + '.csv'))
    if chooser.showSaveDialog(self.root) != swing.JFileChooser.APPROVE_OPTION:
      return
    path = chooser.getSelectedFile().getPath()
    encode = lambda v: 'NULL' if v is None else (v if isinstance(v, unicode) else unicode(v)).encode('utf-8')
    with open(path, 'wb') as fh:
      fh.write('\xef\xbb\xbf')
      writer = csv.writer(fh)
      writer.writerow([encode(c) for c in table[0]])
      for r in table[1]:
        writer.writerow([encode(v) for v in r])
    self.dumpTitle.setText('Saved %d rows to %s' % (len(table[1]), path))

  def stopTask(self, e=None):
    t = self.selected
    if t is None or t.status != 'Running':
      return
    self.bStop.setEnabled(False)
    inBackground(self.killTask, t)

  def killTask(self, t):
    try:
      resp = self.api('/scan/%s/kill' % t.id)
      print ('Scan stopped for ID: ' if resp.get('success') else 'Failed to stop scan on ID, likely already completed: ') + t.id + '\n'
    except:
      print 'Failed to stop scan on ID: ' + t.id + ', likely already completed\n'
    try:
      self.collect(t, True)
    except:
      pass
    t.status = 'Stopped'
    onEdt(self.taskChanged, t)

  def removeTask(self, e=None):
    t = self.selected
    row = self.rowOf(t)
    if row < 0:
      return
    with self.lock:
      self.tasks.remove(t)
    self.selected = None
    self.taskModel.removeRow(row)
    self.showTask(None)
    print 'Removing task ' + t.id + '\n'
    inBackground(self.deleteTask, t)

  def deleteTask(self, t):
    try:
      if t.status == 'Running':
        self.api('/scan/%s/kill' % t.id, timeout=3)
      self.api('/task/%s/delete' % t.id, timeout=3)
    except:
      pass

  def knownSchema(self, url):
    # Databases and tables found by any task on this URL
    dbs = []
    tables = OrderedDict()
    current = None
    for t in list(self.tasks):
      if t.url != url or t.result is None:
        continue
      r = t.result
      current = current or r.currentDb
      for db in ([r.currentDb] if r.currentDb else []) + list(r.dbs) + list(r.tables.keys()):
        if db not in dbs:
          dbs.append(db)
      for db, names in r.tables.items():
        for name in names:
          if name not in tables.setdefault(db, []):
            tables[db].append(name)
    return dbs, tables, current

  def dumpDialog(self, e=None):
    t = self.selected
    if t is None or t.result is None or not t.result.vulnerable:
      return

    dbs, tables, current = self.knownSchema(t.url)
    cDb = swing.JComboBox(dbs)
    cDb.setEditable(True)
    cDb.setSelectedItem(current or (dbs[0] if dbs else ''))
    cTbl = swing.JComboBox()
    cTbl.setEditable(True)

    def refreshTables(event=None):
      db = unicode(cDb.getEditor().getItem() or '').strip()
      cTbl.removeAllItems()
      cTbl.addItem('(all tables)')
      for name in tables.get(db, []):
        cTbl.addItem(name)
    cDb.addActionListener(Action(refreshTables))
    refreshTables()

    fCol = swing.JTextField(16)
    chkAll = swing.JCheckBox('Dump all databases')
    chkSkip = swing.JCheckBox('Skip system databases', True)

    f = Form()
    f.row('Database', cDb)
    f.row('Table(s)', cTbl)
    f.row('Column(s)', fCol)
    f.row('', hbox(chkAll, chkSkip))
    f.full(swing.JLabel('Empty Database = current database. Not sure of the names? List databases, then List tables.'), top=8)
    # Folded; starts at the selected task's values
    bold = []
    s = Accordion(bold, f).section('Speed and log')
    speed, rows = speedRows(f, t.options)
    s.add(rows)
    f.finish()
    self._callbacks.customizeUiComponent(f.panel)
    for c in bold:
      c.setFont(c.getFont().deriveFont(Font.BOLD))

    # Buttons in the order you use them; Dump stays the default
    actions = ['dbs', 'tables', 'dump']
    choice = swing.JOptionPane.showOptionDialog(self.root, f.panel, 'Dump from task ' + t.id[:8], swing.JOptionPane.DEFAULT_OPTION,
                                                swing.JOptionPane.PLAIN_MESSAGE, None,
                                                ['List databases', 'List tables', 'Dump', 'Cancel'], 'Dump')
    if not 0 <= choice < len(actions):
      return

    tbl = unicode(cTbl.getEditor().getItem() or '').strip()
    self.followUp(t, actions[choice], unicode(cDb.getEditor().getItem() or '').strip(), '' if tbl == '(all tables)' else tbl,
                  fCol.getText().strip(), chkAll.isSelected(), chkSkip.isSelected(),
                  OrderedDict([(k, box.getSelectedItem()) for k, box in speed.items()]))

  def followUp(self, t, action, db, tbl, col, everything, skipSys, speed=None):
    # New task on the same request that reuses sqlmap's stored session, so detection is not repeated.
    # action is 'dbs' (list databases), 'tables' (list tables) or 'dump'. speed replaces the parent's threads, timeout etc.
    opts = OrderedDict([(k, v) for k, v in t.options.items() if k not in ENUM_KEYS])
    opts.update(speed or {})
    opts['getBanner'] = True
    if action == 'dbs':
      opts['getDbs'] = True
      job = 'List databases'
    elif action == 'tables':
      opts['getTables'] = True
      job = 'List tables' + (' in ' + db if db else '')
      if db:
        opts['db'] = db
    elif everything:
      opts['dumpAll'] = True
      job = 'Dump all databases'
    else:
      opts['dumpTable'] = True
      for key, value in (('db', db), ('tbl', tbl), ('col', col)):
        if value:
          opts[key] = value
      job = 'Dump ' + ((db or 'current DB') + '.' + tbl if tbl else (db or 'current DB') + ' (all tables)')
    if skipSys and action != 'dbs':
      opts['excludeSysDbs'] = True
    opts['answers'] = ANSWERS

    self.taskTitle.setText('Starting: ' + job + '...')
    inBackground(self.submit, job, t.url, opts, t.message, t.messageUrl, t.id, self.apiConfig())
