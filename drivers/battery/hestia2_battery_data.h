#define CAPACITY_MAX			1000
#define CAPACITY_MAX_MARGIN     30
#define CAPACITY_MIN			0

static struct battery_data_t samsung_battery_data[] = {
	/* SDI battery data (High voltage 4.35V) */
	{
		.Capacity = 0x351E,	/* 6800mAh*/
		.low_battery_comp_voltage = 3500,
		.low_battery_table = {
			/* range, slope, offset */
			{-5000,	0,	0},	/* dummy for top limit */
			{-1250, 0,	3320},
			{-750, 97,	3451},
			{-100, 96,	3461},
			{0, 0,	3456},
		},
		.temp_adjust_table = {
			/* range, slope, offset */
			{47000, 122,	8950},
			{60000, 200,	51000},
			{100000, 0,	0},	/* dummy for top limit */
		},
		.type_str = "SDI",
	}
};

static sec_bat_adc_table_data_t temp_table[] = {
	{25954,	900},
	{26005,	890},
	{26052,	880},
	{26105,	870},
	{26151,	860},
	{26207,	850},
	{26253,	840},
	{26302,	830},
	{26354,	820},
	{26405,	810},
	{26454,	800},
	{26503,	790},
	{26554,	780},
	{26602,	770},
	{26657,	760},
	{26691,	750},
	{26757,	740},
	{26823,	730},
	{26889,	720},
	{26955,	710},
	{27020,	700},
	{27081,	690},
	{27142,	680},
	{27203,	670},
	{27264,	660},
	{27327,	650},
	{27442,	640},
	{27557,	630},
	{27672,	620},
	{27787,	610},
	{27902,	600},
	{28004,	590},
	{28106,	580},
	{28208,	570},
	{28310,	560},
	{28415,	550},
	{28608,	540},
	{28801,	530},
	{28995,	520},
	{28944,	510},
	{28893,	500},
	{29148,	490},
	{29347,	480},
	{29546,	470},
	{29746,	460},
	{29911,	450},
	{30076,	440},
	{30242,	430},
	{30490,	420},
	{30738,	410},
	{30986,	400},
	{31101,	390},
	{31216,	380},
	{31331,	370},
	{31446,	360},
	{31561,	350},
	{31768,	340},
	{31975,	330},
	{32182,	320},
	{32389,	310},
	{32596,	300},
	{32962,	290},
	{32974,	280},
	{32986,	270},
	{33744,	260},
	{33971,	250},
	{34187,	240},
	{34403,	230},
	{34620,	220},
	{34836,	210},
	{35052,	200},
	{35261,	190},
	{35470,	180},
	{35679,	170},
	{35888,	160},
	{36098,	150},
	{36317,	140},
	{36537,	130},
	{36756,	120},
	{36976,	110},
	{37195,	100},
	{37413,	90},
	{37630,	80},
	{37848,	70},
	{38065,	60},
	{38282,	50},
	{38458,	40},
	{38635,	30},
	{38811,	20},
	{38987,	10},
	{39163,	0},
	{39317,	-10},
	{39470,	-20},
	{39624,	-30},
	{39777,	-40},
	{39931,	-50},
	{40065,	-60},
	{40199,	-70},
	{40333,	-80},
	{40467,	-90},
	{40601,	-100},
	{40728,	-110},
	{40856,	-120},
	{40983,	-130},
	{41110,	-140},
	{41237,	-150},
	{41307,	-160},
	{41378,	-170},
	{41448,	-180},
	{41518,	-190},
	{41588,	-200},
};

#define TEMP_HIGHLIMIT_THRESHOLD_EVENT		800
#define TEMP_HIGHLIMIT_RECOVERY_EVENT		750
#define TEMP_HIGHLIMIT_THRESHOLD_NORMAL		800
#define TEMP_HIGHLIMIT_RECOVERY_NORMAL		750
#define TEMP_HIGHLIMIT_THRESHOLD_LPM		800
#define TEMP_HIGHLIMIT_RECOVERY_LPM		750

#define TEMP_HIGH_THRESHOLD_EVENT  600
#define TEMP_HIGH_RECOVERY_EVENT   490
#define TEMP_LOW_THRESHOLD_EVENT   (-50)
#define TEMP_LOW_RECOVERY_EVENT    1
#define TEMP_HIGH_THRESHOLD_NORMAL 600
#define TEMP_HIGH_RECOVERY_NORMAL  490
#define TEMP_LOW_THRESHOLD_NORMAL  (-50)
#define TEMP_LOW_RECOVERY_NORMAL   1
#define TEMP_HIGH_THRESHOLD_LPM    600
#define TEMP_HIGH_RECOVERY_LPM     490
#define TEMP_LOW_THRESHOLD_LPM     (-50)
#define TEMP_LOW_RECOVERY_LPM      1

#if defined(CONFIG_BATTERY_SWELLING)
#define BATT_SWELLING_HIGH_TEMP_BLOCK		550
#define BATT_SWELLING_HIGH_TEMP_RECOV		460
#define BATT_SWELLING_LOW_TEMP_BLOCK		100
#define BATT_SWELLING_LOW_TEMP_RECOV		150
#define BATT_SWELLING_RECHG_VOLTAGE		4150
#define BATT_SWELLING_BLOCK_TIME	10 * 60 /* 10 min */
#endif
