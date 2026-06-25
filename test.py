import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import altair as alt

# ✅ 페이지 설정 + 색 꾸미기
st.set_page_config(
    page_title="😊 Mood Dashboard",
    page_icon="😊",
    layout="wide"
)

# ✅ 커스텀 CSS로 색 꾸미기
st.markdown("""
    <style>
    .main { background-color: #f0f4f8; }
    .stTabs [data-baseweb="tab"] {
        font-size: 16px;
        font-weight: bold;
        color: #4a4a8a;
    }
    .stTabs [aria-selected="true"] {
        background-color: #d0d8ff;
        border-radius: 8px 8px 0 0;
    }
    </style>
""", unsafe_allow_html=True)


# 데이터 로드 함수
def load_dataset():
    data = pd.read_csv('Daylio_Abid_with_synthetic_weather.csv')
    table = pd.DataFrame(
        {'Counts': [data.shape[0], data.shape[1]]},
        index=['Rows', 'Columns']
    )
    return data, table


# 전처리 함수
def preprocess_data(data):
    data['date_iso'] = pd.to_datetime(data['date_iso'], errors='coerce')
    data['weekday'] = data['date_iso'].dt.day_name()

    data['Hour'] = pd.to_datetime(
        data['time'].astype(str).str.strip(),
        format='%I:%M %p',
        errors='coerce'
    ).dt.hour

    def hour_label(hour):
        if pd.isna(hour):
            return None
        hour = int(hour)
        period = 'AM' if hour < 12 else 'PM'
        hour12 = hour % 12
        if hour12 == 0:
            hour12 = 12
        return f'{hour12}{period}'

    data['TimeSlot'] = data['Hour'].apply(hour_label)
    data['mood_score'] = pd.to_numeric(data['mood_score'], errors='coerce')
    data['temperature_c'] = pd.to_numeric(data['temperature_c'], errors='coerce')
    data['humidity_percent'] = pd.to_numeric(data['humidity_percent'], errors='coerce')
    data['precipitation_mm'] = pd.to_numeric(data['precipitation_mm'], errors='coerce')

    return data


# 요일별 / 시간대별 평균 기분 점수
def plot_weekday_hourly_mood_score(data):
    weekday_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    weekday_avg = data.groupby('weekday')['mood_score'].mean().reindex(weekday_order)
    hour_avg = data.groupby('Hour')['mood_score'].mean().reindex(range(24))

    def hour_label(hour):
        period = 'AM' if hour < 12 else 'PM'
        hour12 = hour % 12
        if hour12 == 0:
            hour12 = 12
        return f'{hour12}{period}'

    hour_labels = [hour_label(h) for h in range(24)]

    st.subheader('📅 Average Mood Score by Day of the Week')
    fig1, ax1 = plt.subplots(figsize=(12, 5))
    ax1.bar(weekday_avg.index, weekday_avg.values, color='#6c8ebf')
    ax1.set_title('Average Mood Score by Day of the Week')
    ax1.set_xlabel('Day of the Week')
    ax1.set_ylabel('Average Mood Score')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=30)
    plt.tight_layout()
    st.pyplot(fig1)

    st.subheader('🕐 Average Mood Score by Hour of the Day')
    fig2, ax2 = plt.subplots(figsize=(12, 5))
    ax2.plot(hour_avg.index, hour_avg.values, marker='o', color='#e07b54')
    ax2.set_title('Average Mood Score by Hour of the Day')
    ax2.set_xlabel('Hour of the Day')
    ax2.set_ylabel('Average Mood Score')
    ax2.set_xticks(range(24))
    ax2.set_xticklabels(hour_labels, rotation=45)
    ax2.grid(axis='both', linestyle='--', alpha=0.7)
    plt.tight_layout()

    return fig2


# 선택한 mood 분포 파이차트
def plot_filtered_mood(data, moods):
    filtered_data = data[data['mood'].isin(moods)]
    mood_counts = filtered_data['mood'].value_counts()

    fig, ax = plt.subplots(figsize=(8, 8))
    colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99','#c2c2f0']
    ax.pie(
        mood_counts,
        labels=mood_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=colors[:len(mood_counts)]
    )
    ax.set_title('Selected Mood Distribution')
    plt.tight_layout()
    return fig


# 활동 TOP 10
def plot_top_activities(data):
    activity_series = data['activities'].dropna().str.split(r'[,|]').explode()
    activity_series = activity_series.str.strip()
    activity_series = activity_series[activity_series != '']
    top_activities = activity_series.value_counts().head(10)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(top_activities.index, top_activities.values, color='#82c4a0')
    ax.set_title('Top 10 Activities')
    ax.set_xlabel('Activity')
    ax.set_ylabel('Count')
    ax.tick_params(axis='x', rotation=45)
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    return fig


# 활동별 평균 기분 점수
def plot_activity_avg_mood(data):
    activity_data = data[['activities', 'mood_score']].dropna().copy()
    activity_data['activity'] = activity_data['activities'].str.split(r'[,|]')
    activity_data = activity_data.explode('activity')
    activity_data['activity'] = activity_data['activity'].str.strip()
    activity_data = activity_data[activity_data['activity'] != '']
    activity_avg = activity_data.groupby('activity')['mood_score'].mean()
    activity_avg = activity_avg.sort_values(ascending=False).head(10)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(activity_avg.index, activity_avg.values, color='#a78bdb')
    ax.set_title('Average Mood Score by Activity')
    ax.set_xlabel('Activity')
    ax.set_ylabel('Average Mood Score')
    ax.tick_params(axis='x', rotation=45)
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    return fig


# 날씨 조건 중첩 필터링
def filter_weather_data(data, start_date, end_date, temp_range, humidity_range, precip_range):
    start_date = pd.to_datetime(start_date)
    end_date = pd.to_datetime(end_date)

    filtered_data = data[
        (data['date_iso'] >= start_date) &
        (data['date_iso'] <= end_date) &
        (data['temperature_c'] >= temp_range[0]) &
        (data['temperature_c'] <= temp_range[1]) &
        (data['humidity_percent'] >= humidity_range[0]) &
        (data['humidity_percent'] <= humidity_range[1]) &
        (data['precipitation_mm'] >= precip_range[0]) &
        (data['precipitation_mm'] <= precip_range[1])
    ]
    return filtered_data


# 필터링된 데이터의 weather별 평균 mood_score
def plot_filtered_weather_mood(data):
    weather_avg = data.groupby('weather')['mood_score'].mean()

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(weather_avg.index, weather_avg.values, color='#f0a060')
    ax.set_title('Average Mood Score by Weather')
    ax.set_xlabel('Weather')
    ax.set_ylabel('Average Mood Score')
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    return fig


# 히트맵
def make_heatmap(data):
    data = data.copy()
    data['year'] = data['date_iso'].dt.year
    data['month'] = data['date_iso'].dt.month
    data['day'] = data['date_iso'].dt.day

    years = sorted(data['year'].dropna().unique().tolist())

    # ✅ session_state로 선택 연도 기억
    if 'selected_year' not in st.session_state:
        st.session_state['selected_year'] = years[0]

    selected_year = st.selectbox(
        '📆 Select Year',
        options=years,
        index=years.index(st.session_state['selected_year']),
        key='selected_year'
    )

    filtered = data[data['year'] == selected_year]
    daily_avg = filtered.groupby(['month', 'day'])['mood_score'].mean().reset_index()

    month_names = {1:'Jan',2:'Feb',3:'Mar',4:'Apr',5:'May',6:'Jun',
                   7:'Jul',8:'Aug',9:'Sep',10:'Oct',11:'Nov',12:'Dec'}
    daily_avg['month_name'] = daily_avg['month'].map(month_names)

    heatmap = alt.Chart(daily_avg).mark_rect().encode(
        y=alt.Y('month_name:O',
                sort=list(month_names.values()),
                axis=alt.Axis(title='Month', titleFontSize=18,
                              titlePadding=15, titleFontWeight=900, labelAngle=0)),
        x=alt.X('day:O',
                axis=alt.Axis(title='Day', titleFontSize=18, titlePadding=15)),
        color=alt.Color('mood_score:Q',
                        scale=alt.Scale(scheme='blues', domain=[1, 5]),
                        legend=alt.Legend(title='Mood Score')),
        stroke=alt.value('black'),
        strokeWidth=alt.value(0.25),
        tooltip=[
            alt.Tooltip('month_name:O', title='Month'),
            alt.Tooltip('day:O', title='Day'),
            alt.Tooltip('mood_score:Q', title='Mood Score', format='.2f')
        ]
    ).properties(
        width=900,
        height=300
    ).configure_axis(
        labelFontSize=12,
        titleFontSize=12
    )

    st.altair_chart(heatmap, use_container_width=True)


# Streamlit 앱
def main():
    st.title("😊 MY DAILY MOOD DATA Dashboard")
    st.sidebar.title("🔧 Filters and Options")

    data, table = load_dataset()
    data = preprocess_data(data)

    st.sidebar.write("### 📊 Dataset Overview")
    st.sidebar.table(table)

    # ✅ session_state로 선택된 탭 기억
    if 'active_tab' not in st.session_state:
        st.session_state['active_tab'] = 0

    st.write("### 🔍 Explore Mood Data")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📅 Weekday & Hourly",
        "😄 Mood Distribution",
        "🏃 Activities",
        "🌤️ Weather Filter",
        "🗓️ Mood Heatmap"
    ])

    with tab1:
        st.write("#### 📅 Weekday & Hourly Mood Score")
        fig = plot_weekday_hourly_mood_score(data)
        st.pyplot(fig)

    with tab2:
        st.write("#### 😄 Mood Distribution")
        mood_options = data['mood'].dropna().unique().tolist()

        # ✅ session_state로 선택된 mood 기억
        if 'selected_moods' not in st.session_state:
            st.session_state['selected_moods'] = mood_options

        selected_moods = st.multiselect(
            'Select Mood 😊',
            mood_options,
            default=st.session_state['selected_moods'],
            key='selected_moods'
        )

        if selected_moods:
            fig = plot_filtered_mood(data, selected_moods)
            st.pyplot(fig)
        else:
            st.warning('⚠️ 하나 이상의 mood를 선택하세요.')

    with tab3:
        st.write("#### 🏃 Activity Analysis")
        fig1 = plot_top_activities(data)
        st.pyplot(fig1)
        fig2 = plot_activity_avg_mood(data)
        st.pyplot(fig2)

    with tab4:
        st.write("#### 🌤️ Weather-based Mood Filter")

        start_date = st.date_input('📅 Start Date', data['date_iso'].min().date())
        end_date = st.date_input('📅 End Date', data['date_iso'].max().date())

        temp_range = st.slider(
            '🌡️ Temperature Range (°C)',
            float(data['temperature_c'].min()),
            float(data['temperature_c'].max()),
            (float(data['temperature_c'].min()), float(data['temperature_c'].max()))
        )

        humidity_range = st.slider(
            '💧 Humidity Range (%)',
            int(data['humidity_percent'].min()),
            int(data['humidity_percent'].max()),
            (int(data['humidity_percent'].min()), int(data['humidity_percent'].max()))
        )

        precip_range = st.slider(
            '🌧️ Precipitation Range (mm)',
            float(data['precipitation_mm'].min()),
            float(data['precipitation_mm'].max()),
            (float(data['precipitation_mm'].min()), float(data['precipitation_mm'].max()))
        )

        filtered_data = filter_weather_data(
            data, start_date, end_date, temp_range, humidity_range, precip_range
        )

        st.write('🔎 Filtered Data Count:', len(filtered_data))

        if len(filtered_data) > 0:
            fig = plot_filtered_weather_mood(filtered_data)
            st.pyplot(fig)
        else:
            st.warning('⚠️ 선택한 조건에 해당하는 데이터가 없습니다.')

    with tab5:
        st.write("#### 🗓️ Daily Mood Score Heatmap")
        make_heatmap(data)


if __name__ == "__main__":
    main()
