import pdfkit
import socket
import json
from datetime import datetime
import os
import pandas as pd
# import dfler from output_dir


def build_head(report_html):
  report = open(report_html, 'a')
  report.write("""
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Forensic Report</title>
    </head>
  """)
  report.close()


def build_foot(config, report_html):
  report = open(report_html, 'a')
  report.write("""
      </body>
    <footer id="footer">
      <span class="timestamp"> <em>Generated using adfler {app_version}</em> </span>
    </footer>
  </html>
  """.format(app_version=config['app_version']))
  report.close()


def build_style(report_html):
  report = open(report_html, 'a')
  report.write("""
  <style>
    body {
      font-family: Arial, Helvetica, sans-serif;
    }
    .text-center {
      text-align: center;
    }
    th {
      text-align: center;
    }

    th,
    td {
      padding-top: 5px;
      padding-bottom: 5px;
      padding-left: 8px;
      padding-right: 8px;
    }

    /* table,
    th,
    td {
      border: 1px solid #000;
    } */

    .timeline {
      font-family: Arial, Helvetica, sans-serif;
      font-size: 1.2em;
      text-align: center;
      font-weight: bold;
    }

    table.fixed {
      table-layout: fixed;
    }
    table.fixed td {
      overflow: hidden;
    }

    table {
      border-collapse: collapse;
      font-family: Arial, Helvetica, sans-serif;
      font-size: 0.95em;
    }

    table.table-timeline {
      width: 100%;
      font-size: 1em;
    }

    table.table-timeline > thead { display: table-header-group; }
    table.table-timeline > tfoot { display: table-row-group; }
    table.table-timeline > tbody > tr { page-break-inside: avoid; }

    table.table-timeline,
    table.table-timeline > thead > tr > th,
    table.table-timeline > tbody > tr > td {
      border: 1px solid #000;
    }

    table.table-timeline > thead > tr > th {
      font-weight: bold;
    }

    table.table-timeline > tbody > tr > td:first-child {
      text-align: center;
    }

    .outside {
      color: #000;
    }

    .event {
      color: red;
    }

    .nonevent {
      color: blue;
    }

    .bold {
      text-emphasis-color: red;
    }

    #footer {
      margin-top: 7px;
      display: flex;
      justify-content: space-between;
    }

    .content-color {
      color: #2b4f60;
    }

    .timestamp {
      color: grey;
      font-size: small;
    }
    .page-number {
      width: 50%;
      text-align: right;
      margin-right: 5px;
    }

    .report-title {
      font-weight: bold;
      text-align: left;
      font-size: 1.8em;
      color: #0e5e6f;
    }

    .title-color {
      color: #0e5e6f;
      font-size: 1em;
    }

    #metadata {
      margin-top: 3em;
    }

    #table-metadata {
      border: none !important;
      width: 30%;
      font-size: 1em;
      margin-left: -8px;
    }

    #color-legend.table-timeline {
      width: 9%;
      border: none !important;
    }

    .box {
      float: left;
      width: 20px;
      height: 20px;
      margin: 5px;
      border: 1px solid rgba(0, 0, 0, 0.2);
    }

    .outside-box {
      background: #000;
    }

    .event-box {
      background: red;
    }

    .nonevent-box {
      background: blue;
    }

    .break-before {
      page-break-before: always;
    }
  </style>
  """)
  report.close()


def build_report_header(config, report_html):
  now = datetime.now()
  now = now.strftime("%m/%d/%Y %H:%M:%S")
  hostname = socket.gethostname()
  raw_list = open(config['output_dir'] + '/raw_list.json')
  raw_list = json.load(raw_list)
  flat_list = [item for sublist in raw_list for item in sublist]
  report = open(report_html, 'a')
  report.write("""
  <body>
    <h4 class="report-title">Drone Forensic Report</h4>
    <hr style="margin-top: -2em" />
    <span class="timestamp"
      >This report is generated on: {timestamp}</span
    >
    <section id="metadata">
      <table id="table-metadata fixed">
        <col width="30%" />
        <col width="70%" />
        <tr>
          <td>Computer Name</td>
          <td>{hostname}</td>
        </tr>
        <tr>
          <td>Report Type</td>
          <td>Entity Recognition</td>
        </tr>
        <tr>
          <td>Number of log files</td>
          <td>{num_evidence}</td>
        </tr>
      </table>
    </section>
  """.format(timestamp=now, hostname=hostname, num_evidence=len(flat_list)))
  report.close()


def build_source_evidence(config, report_html):
  content = """
    <section>
      <h4 class="title-color" style="margin-top: 3em">Source evidence</h4>
      <hr style="margin-top: -1em" />
      <ul class="content-color">
  """
  raw_list = open(config['output_dir'] + '/raw_list.json')
  raw_list = json.load(raw_list)
  flat_list = [item for sublist in raw_list for item in sublist]

  for item in flat_list:
    content = content + """
        <li>{filename}</li>
    """.format(filename=item) 
    # print("<li>{filename}</li>".format(filename=item))
  content = content + """
      </ul>
    </section>
  """
  report = open(report_html, 'a')
  report.write(content)
  report.close()


def build_ner_result(statistics, report_html):
  report = open(report_html, 'a')
  content = """
    <section>
      <h4 class="title-color" style="margin-top: 3em">Recognition Results</h4>
      <hr style="margin-top: -1em" />
      <table id="table-metadata fixed">
        <col width="40%" />
        <col width="10%" />
        <col width="40%" />
        <col width="10%" />
    """
  counter = 1
  for key, value in statistics.items():
    if (counter % 2 == 1):
      content = content + """
        <tr>
          <td>Number of {key}</td>
          <td>{value}</td>
      """.format(key=key, value=value)
    else:
      content = content + """
          <td>Number of {key}</td>
          <td>{value}</td>
        </tr>
      """.format(key=key, value=value)
    counter = counter + 1
  content = content + """
      </table>
    </section>
  """
  report.write(content)
  report.close()

def build_th(report_html):
  report = open(report_html, 'a')
  report.write("""
  <section class="break-before">
    <h5 class="timeline">Highlights Color Code</h5>
      <table class="table-timeline fixed">
        <col width="10%" />
        <col width="20%" />
        <col width="70%" />
        <thead>
          <tr>
            <th>Color Code</th>
            <th>Entity Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <span class="box event-box"></span>
            </td>
            <td>
              <span class="event">Event</span>
            </td>
            <td>
              Words/phrases that indicate an event has occurred.
            </td>
          </tr>
          <tr>
            <td>
              <span class="box nonevent-box"></span>
            </td>
            <td>
              <span class="nonevent">NonEvent</span>
            </td>
            <td>
              Words/phrases that denote routine or non-event information.
            </td>
          </tr>
        </tbody>
      </table>
      <h5 class="timeline" style="margin-top: 3em">
        Highlighted Forensic Timeline
      </h5>
      <table class="table-timeline fixed">
        <col width="30%" />
        <col width="70%" />
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
      """)
  report.close()

def statistics(config, ner_result):
  entities_json = open('./flight_logs/entities.json')
  entities = json.load(entities_json)

  word_list = []
  tag_list = []
  for record in entities:
      timestamp = record['timestamp']
      messages = record['entities']
      for message in messages:
          for word, tag in message.items():
              word_list.append(word)
              tag_list.append(tag)

  ner_result = pd.DataFrame(list(zip(word_list, tag_list)), columns =['word', 'tag'])
  entity_df = ner_result[ner_result['tag'] != 'O']
  non_entity_df = ner_result[ner_result['tag'] == 'O']
  event = ['B-Event', 'I-Event', 'E-Event', 'S-Event']
  event_df = ner_result[ner_result['tag'].isin(event)]
  nonevent = ['B-NonEvent', 'I-NonEvent', 'E-NonEvent', 'S-NonEvent']
  nonevent_df = ner_result[ner_result['tag'].isin(nonevent)]
  entities_json.close()
  return {
    'message': len(entities),
    'entity': len(entity_df),
    'non_entity': len(non_entity_df),
    'event': len(event_df),
    'nonevent': len(nonevent_df),
  }


def build_forensic_table(config, report_html):
  # Opening JSON file
  timeline_file = open(config['output_dir'] + '/ner_result.json')
  timeline = json.load(timeline_file)
  
  build_th(report_html)
  # Loop the table
  build_tr(timeline, report_html)
  # Closing file
  timeline_file.close()


def build_tr(records, report_html):
  report = open(report_html, 'a')
  content = ""
  for record in records:
    timestamp = record['timestamp']
    content = content + """
          <tr>
            <td>{timestamp}</td>
            <td>
    """.format(timestamp=timestamp)
    messages = record['entities']
    for message in messages:
      for word, tag in message.items():
        if tag == 'O':
          # generate tag span O
          content = content + """
              <span class="{tag}">{token}</span>
          """.format(tag='outside', token=word)
        elif tag in ['B-Event', 'I-Event', 'E-Event', 'S-Event']:
          content = content + """
              <span class="{tag}">{token}</span>
          """.format(tag='event', token=word)
        elif tag in ['B-NonEvent', 'I-NonEvent', 'E-NonEvent', 'S-NonEvent']:
          content = content + """
              <span class="{tag}">{token}</span>
          """.format(tag='nonevent', token=word)

    content = content + """
            </td>
          </tr>
    """  
  content = content + """
        </tbody>
      </table>
    </section>
  """
  report.write(content)
  report.close()

def statistical_analysis(config):
  # Opening JSON file
  ner_result_json = open(config['output_dir'] + '/ner_result.json')
  ner_result = json.load(ner_result_json)

  word_list = []
  tag_list = []
  for record in ner_result:
      timestamp = record['timestamp']
      messages = record['entities']
      for message in messages:
          for word, tag in message.items():
              word_list.append(word)
              tag_list.append(tag)
  
  ner_result_df = pd.DataFrame(list(zip(word_list, tag_list)), columns =['word', 'tag'])
  entity_df = ner_result_df[ner_result_df['tag'] != 'O']
  non_entity_df = ner_result_df[ner_result_df['tag'] == 'O']
  event = ['B-Event', 'I-Event', 'E-Event', 'S-Event']
  event_df = ner_result_df[ner_result_df['tag'].isin(event)]
  nonevent = ['B-NonEvent', 'I-NonEvent', 'E-NonEvent', 'S-NonEvent']
  nonevent_df = ner_result_df[ner_result_df['tag'].isin(nonevent)]
  statistics = {
    "message": len(ner_result),
    "entity": len(entity_df),
    "non_entity": len(non_entity_df),
    "token": len(entity_df) + len(non_entity_df),
    "event": len(event_df),
    "nonevent": len(nonevent_df),
  }

  with open(config['output_dir'] + '/statistics.json', 'w') as file:
    json.dump(statistics, file)
  ner_result_json.close()
  return statistics

def build_html(config, filename):
  output_dir = config['output_dir']
  full_path = os.path.join(output_dir, filename + ".html")
  statistics = statistical_analysis(config)

  # sys.stdout = open(full_path, 'w')
  build_head(full_path)
  build_style(full_path)
  build_report_header(config, full_path)
  build_source_evidence(config, full_path)
  build_ner_result(statistics, full_path)
  build_forensic_table(config, full_path)
  build_foot(config, full_path)
  # sys.stdout.close()


def generatePDF(config, filename):
  # Define path to wkhtmltopdf.exe
  # path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
  path_to_wkhtmltopdf = config['wkhtml_path']
  # Define path to input and output file
  output_dir = config['output_dir']
  full_path = os.path.join(output_dir, filename)
  # Point pdfkit configuration to wkhtmltopdf.exe
  config_wkhtml = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)
  # Convert HTML file to PDF
  pdfkit.from_file(full_path + ".html", output_path = full_path + ".pdf", configuration=config_wkhtml)


def generate_report(config):
  # Prepare the filename and outputdir
  # Move to the config, so that every function can access
  # now = datetime.now()
  # now = now.strftime("%d%m%Y_%H%M%S")
  # output_dir = os.path.join("./result", now)
  filename = "forensic_report_"

  build_html(config, filename)
  generatePDF(config, filename)
  
    