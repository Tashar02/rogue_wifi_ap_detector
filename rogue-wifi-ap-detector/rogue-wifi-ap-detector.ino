// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Tashfin Shakeer Rhythm <tashfinshakeerrhythm@gmail.com>.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

/* Hardware PIN definitions */
#define BUZZER_PIN		0
#define BUTTON_PIN		1
#define LED_BLUE		2 /* Normal Activity */
#define LED_ORANGE		3 /* Alert & Danger */
#define I2C_SDA			6
#define I2C_SCL			7

/* Display Settings */
#define SCREEN_WIDTH		128
#define SCREEN_HEIGHT		64
#define OLED_RESET		-1

/* Timing and Threshold Constants */
#define LONG_PRESS_MS		1000
#define DOUBLE_CLICK_MS		300
#define SHORT_PRESS_MS		400
#define DEBOUNCE_DELAY_MS	50
#define SCAN_TIMEOUT_MS		5000
#define PING_THRESHOLD		10
#define FLOOD_THRESHOLD		100

/* Acoustic Frequencies */
#define TONE_FREQ_SINGLE	2400
#define TONE_FREQ_DOUBLE	2100
#define TONE_FREQ_LONG		2500
#define TONE_FREQ_ALARM		2500

/* Utility Macros */
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

/* Honeypot Network Settings */
const char *ap_ssid = "Scarlet ESP32-C6";
const char *ap_pass = "";

/* Global Variables */
uint8_t my_mac[6];
volatile uint32_t total_packet_count = 0;
volatile uint32_t interval_packet_count = 0;
char last_connected_mac[18] = "None";

/* Feature 5 (Port Scan) Variables */
int port_scan_count = 0;
unsigned long last_scan_time = 0;
WiFiServer server_21(21);	/* FTP Honeypot */
WiFiServer server_22(22);	/* SSH Honeypot */
WiFiServer server_80(80);	/* HTTP Honeypot */
WiFiServer server_443(443);	/* HTTPS Honeypot */

WiFiServer *honeypot_servers[] = {
	&server_21,
	&server_22,
	&server_80,
	&server_443,
};

/* State Machine */
enum app_state {
	STATE_MENU,
	STATE_RUN_F1,
	STATE_RUN_F2,
	STATE_RUN_F3,
	STATE_RUN_F4,
	STATE_RUN_F5
};

enum button_action {
	ACTION_SINGLE,
	ACTION_DOUBLE,
	ACTION_LONG,
};

enum app_state state = STATE_MENU;
int menu_index = 0;
const int num_features = 5;

/* Debounced Button Variables */
int button_state = HIGH;
int last_flickerable_state = HIGH;
unsigned long last_debounce_time = 0;

unsigned long btn_press_time = 0;
unsigned long btn_release_time = 0;
bool is_waiting_for_double_click = false;
bool button_handled = false;

/* Non-blocking Timers */
unsigned long last_feature_update = 0;

/* Function Prototypes */
void draw_menu(void);
void handle_button(void);
void execute_action(enum button_action action);
void setup_feature(void);
void exit_feature(void);
void feature_ping_monitor(void);
void feature_data_monitor(void);
void feature_client_logger(void);
void feature_flood_monitor(void);
void feature_portscan_monitor(void);

static void display_begin_frame(void)
{
	display.clearDisplay();
	display.setCursor(0, 0);
	display.setTextColor(SSD1306_WHITE);
}

static void display_end_frame(bool show_exit)
{
	if (show_exit) {
		display.setCursor(0, 56);
		display.println("Dbl click = exit");
	}
	display.display();
}

/* Sniffer & Callbacks */
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt;
	uint8_t *payload;
	bool is_to_me = true;
	int i;

	if (type != WIFI_PKT_DATA)
		return;

	pkt = (wifi_promiscuous_pkt_t *)buf;

	/* Ensure packet is long enough to safely read Address 1 (MAC) at offset 4 */
	if (pkt->rx_ctrl.sig_len < 10)
		return;

	payload = pkt->payload;

	for (i = 0; i < 6; i++) {
		if (payload[4 + i] != my_mac[i]) {
			is_to_me = false;
			break;
		}
	}

	if (is_to_me) {
		total_packet_count++;
		interval_packet_count++;
	}
}

void on_client_connect(WiFiEvent_t event, WiFiEventInfo_t info)
{
	uint8_t *mac = info.wifi_ap_staconnected.mac;

	snprintf(last_connected_mac, sizeof(last_connected_mac),
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void setup(void)
{
	Serial.begin(115200);

	pinMode(BUZZER_PIN, OUTPUT);
	pinMode(LED_BLUE, OUTPUT);
	pinMode(LED_ORANGE, OUTPUT);
	pinMode(BUTTON_PIN, INPUT_PULLUP);

	Wire.begin(I2C_SDA, I2C_SCL);
	if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
		Serial.println(F("SSD1306 allocation failed"));
		for (;;);
	}

	WiFi.onEvent(on_client_connect, ARDUINO_EVENT_WIFI_AP_STACONNECTED);
	draw_menu();
}

void loop(void)
{
	handle_button();

	switch (state) {
	case STATE_RUN_F1:
		feature_ping_monitor();
		break;
	case STATE_RUN_F2:
		feature_data_monitor();
		break;
	case STATE_RUN_F3:
		feature_client_logger();
		break;
	case STATE_RUN_F4:
		feature_flood_monitor();
		break;
	case STATE_RUN_F5:
		feature_portscan_monitor();
		break;
	case STATE_MENU:
	default:
		break;
	}
}

void handle_button(void)
{
	int reading = digitalRead(BUTTON_PIN);
	unsigned long now = millis();
	unsigned long press_duration;

	if (reading != last_flickerable_state) {
		last_debounce_time = now;
		last_flickerable_state = reading;
	}

	if ((now - last_debounce_time) > DEBOUNCE_DELAY_MS) {
		if (reading != button_state) {
			button_state = reading;

			if (button_state == LOW) {
				btn_press_time = now;
				button_handled = false;
			} else {
				btn_release_time = now;
				press_duration = btn_release_time - btn_press_time;

				if (!button_handled) {
					if (press_duration < SHORT_PRESS_MS) {
						if (is_waiting_for_double_click) {
							execute_action(ACTION_DOUBLE);
							is_waiting_for_double_click = false;
						} else {
							is_waiting_for_double_click = true;
						}
					}
				}
			}
		}
	}

	if (button_state == LOW && !button_handled &&
	    (now - btn_press_time > LONG_PRESS_MS)) {
		execute_action(ACTION_LONG);
		button_handled = true;
		is_waiting_for_double_click = false;
	}

	if (is_waiting_for_double_click && (now - btn_release_time > DOUBLE_CLICK_MS) &&
	    button_state == HIGH) {
		execute_action(ACTION_SINGLE);
		is_waiting_for_double_click = false;
	}
}

void execute_action(enum button_action action)
{
	switch (action) {
	case ACTION_SINGLE:
		tone(BUZZER_PIN, TONE_FREQ_SINGLE, 60);
		if (state == STATE_MENU) {
			menu_index = (menu_index + 1) % num_features;
			draw_menu();
		}
		break;

	case ACTION_DOUBLE:
		tone(BUZZER_PIN, TONE_FREQ_DOUBLE, 120);
		if (state != STATE_MENU) {
			exit_feature();
			state = STATE_MENU;
			draw_menu();
		}
		break;

	case ACTION_LONG:
		tone(BUZZER_PIN, TONE_FREQ_LONG, 300);
		if (state == STATE_MENU) {
			state = (enum app_state)(STATE_RUN_F1 + menu_index);
			setup_feature();
		}
		break;
	}
}

void draw_menu(void)
{
	int i;
	const char *items[num_features] = {
		"1. Check AP pings",
		"2. Check AP data",
		"3. Log AP clients",
		"4. AP attack mon",
		"5. Port scan detect"
	};

	display_begin_frame();
	display.println("--- Main menu ---");
	display.println("---------------------");

	for (i = 0; i < num_features; i++) {
		if (i == menu_index) {
			display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
			display.print(">");
		} else {
			display.setTextColor(SSD1306_WHITE);
			display.print(" ");
		}
		display.println(items[i]);
	}

	display.display();
}

void setup_feature(void)
{
	display_begin_frame();
	display.println("Starting AP mode...");
	display.display();

	WiFi.mode(WIFI_OFF);
	delay(100);
	
	total_packet_count = 0;
	interval_packet_count = 0;
	last_feature_update = millis();

	WiFi.mode(WIFI_AP);
	WiFi.softAP(ap_ssid, ap_pass);
	WiFi.softAPmacAddress(my_mac);
	strcpy(last_connected_mac, "None");

	if (state == STATE_RUN_F1 || state == STATE_RUN_F2 || state == STATE_RUN_F4) {
		esp_wifi_set_promiscuous(true);
		esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
	}

	if (state == STATE_RUN_F5) {
		server_21.begin();
		server_22.begin();
		server_80.begin();
		server_443.begin();
		port_scan_count = 0;
	}
}

void exit_feature(void)
{
	esp_wifi_set_promiscuous(false);
	esp_wifi_set_promiscuous_rx_cb(NULL);

	server_21.end();
	server_22.end();
	server_80.end();
	server_443.end();

	WiFi.softAPdisconnect(true);
	WiFi.mode(WIFI_OFF);
	digitalWrite(LED_BLUE, LOW);
	digitalWrite(LED_ORANGE, LOW);
}

void feature_ping_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 1000)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 1: Ping check");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);

	if (interval_packet_count > PING_THRESHOLD) {
		display.setCursor(0, 35);
		display.println("> Ping detected <");
		digitalWrite(LED_ORANGE, HIGH);
	} else {
		digitalWrite(LED_ORANGE, LOW);
	}

	display.setCursor(0, 56);
	display.print("Pkts/sec: ");
	display.println(interval_packet_count);
	display.display();

	interval_packet_count = 0;
}

void feature_data_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 200)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 2: Data check");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);

	display.setCursor(0, 32);
	display.print("Total Rx: ");
	display.println(total_packet_count);

	/* Flash Blue LED if there is active data flow in this interval */
	if (interval_packet_count > 0)
		digitalWrite(LED_BLUE, HIGH);
	else
		digitalWrite(LED_BLUE, LOW);

	interval_packet_count = 0;

	display_end_frame(true);
}

void feature_client_logger(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 500)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 3: Client log");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.println("Last connected:");
	display.println(last_connected_mac);

	if (strcmp(last_connected_mac, "None") != 0)
		digitalWrite(LED_ORANGE, HIGH);
	else
		digitalWrite(LED_ORANGE, LOW);

	display_end_frame(true);
}

void feature_flood_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 1000)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 4: Flood mon");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.print("IP: ");
	display.println(WiFi.softAPIP());

	display.setCursor(0, 36);
	display.print("Traffic rate: ");
	display.println(interval_packet_count);

	if (interval_packet_count > FLOOD_THRESHOLD) {
		display.println(">> Flood attack! <<");
		digitalWrite(LED_ORANGE, HIGH);
		digitalWrite(LED_BLUE, LOW);
		tone(BUZZER_PIN, TONE_FREQ_ALARM, 500);
	} else {
		digitalWrite(LED_ORANGE, LOW);
	}

	display_end_frame(true);

	interval_packet_count = 0;
}

void feature_portscan_monitor(void)
{
	bool scan_hit = false;
	static unsigned long last_beep_time = 0;
	unsigned long now = millis();
	WiFiClient c;
	int i;

	/* Check for incoming connections on the honeypot array */
	for (i = 0; i < ARRAY_SIZE(honeypot_servers); i++) {
		if (!honeypot_servers[i]->hasClient())
			continue;

		c = honeypot_servers[i]->accept();
		c.flush();
		c.stop();
		scan_hit = true;
	}

	if (scan_hit) {
		port_scan_count++;
		last_scan_time = now;

		if (now - last_beep_time > 300) {
			tone(BUZZER_PIN, TONE_FREQ_ALARM, 150);
			last_beep_time = now;
		}
	}

	if (now - last_feature_update < 500)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 5: Port Scan");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.print("IP: ");
	display.println(WiFi.softAPIP());

	display.setCursor(0, 36);
	display.print("Honeypot Ports: 4");

	if (port_scan_count > 0) {
		display.setCursor(0, 46);
		display.println(">> SCAN DETECTED <<");
		digitalWrite(LED_ORANGE, HIGH);
	} else {
		digitalWrite(LED_ORANGE, LOW);
	}

	display_end_frame(true);

	if (port_scan_count > 0 && (now - last_scan_time > SCAN_TIMEOUT_MS)) {
		port_scan_count = 0;
		digitalWrite(LED_ORANGE, LOW);
	}
}
