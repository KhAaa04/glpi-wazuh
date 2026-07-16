import json
import requests
from flask import Flask, request
import datetime

app = Flask(__name__)

GLPI_URL = 'http://10.200.178.85:8081/apirest.php/'
GLPI_APP_TOKEN = 'sP5gKzyCBDWi9ALWuT6o8ZJPT4yzdyGGtmDR55w6'
GLPI_USER = 'glpi'
GLPI_PASSWORD = 'glpi'

def get_glpi_session():
    """Получение сессии через логин и пароль"""
    headers = {
        'Content-Type': 'application/json',
        'App-Token': GLPI_APP_TOKEN
    }
    # Используем параметры login и password в теле запроса
    data = {
        'login': GLPI_USER,
        'password': GLPI_PASSWORD
    }
    response = requests.get(GLPI_URL + 'initSession', headers=headers, data=json.dumps(data))
    
    if response.status_code == 200:
        session_token = response.json()['session_token']
        print(f"[{datetime.datetime.now()}] Сессия получена")
        return session_token
    else:
        print(f"[{datetime.datetime.now()}] Ошибка авторизации: {response.text}")
        return None

def create_ticket(session_token, title, content):
    headers = {
        'Content-Type': 'application/json',
        'Session-Token': session_token,
        'App-Token': GLPI_APP_TOKEN
    }
    data = {
        'input': {
            'name': title,
            'content': content,
            'type': 1,
            'status': 1,
            'urgency': 3
        }
    }
    response = requests.post(GLPI_URL + 'Ticket', headers=headers, data=json.dumps(data))
    return response.status_code, response.text

@app.route('/webhook', methods=['POST'])
def wazuh_webhook():
    alert = request.json
    if not alert:
        return 'No data', 400
    # ВЫВОДИ ВСЁ СОДЕРЖИМОЕ АЛЕРТА
    #print(f"[{datetime.datetime.now()}] Полный алерт: {json.dumps(alert, indent=2)}")

    print(f"[{datetime.datetime.now()}] Получен алерт")

    rule_level = alert.get('rule', {}).get('level', 0)
    rule_desc = alert.get('rule', {}).get('description', 'Unknown')
    agent_ip = alert.get('agent', {}).get('ip', 'Unknown')
    timestamp = alert.get('timestamp', '')
    
    rule_level = alert.get('rule', {}).get('level', 0)
    print(f"[{datetime.datetime.now()}] Уровень алерта: {rule_level}")
    if rule_level >= 1:  # Временно для теста
        session = get_glpi_session()
        if session:
            title = f"[Инцидент ИБ] {rule_desc}"
            content = f"Источник: {agent_ip}\nВремя: {timestamp}\nОписание: {rule_desc}\nУровень: {rule_level}"
            status, response_text = create_ticket(session, title, content)
            print(f"Ответ GLPI: {status} - {response_text}")
            return 'Ticket created', 201
        else:
            return 'Auth failed', 500

    return 'Event ignored', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
