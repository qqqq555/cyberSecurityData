#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
df = pd.read_csv("06_14_2017-ad-dowgin-gdata-1d15765ffee294f27da4865356a994bd.pcap_ISCX.csv")
print(df.shape)
df.head()


# In[2]:


df.info()


# In[5]:


df.columns = df.columns.str.strip()


# In[6]:


# 統計出現次數最多的來源 IP
top_ips = df['Source IP'].value_counts().head(10)
print(top_ips)


# In[16]:


# 統計出現次數最多的來源 IP
top_duration = df[['Source IP', 'Destination IP', 'Flow Duration']].sort_values(by='Flow Duration', ascending=False).head(10)
print(top_duration)


# In[11]:


# 將時間欄位轉換為 pandas 的 datetime 格式
# errors='coerce' 表示如果有格式錯誤的資料就設為 NaT（空值）
df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%Y-%m-%d %H:%M:%S', errors='coerce')
# 從 Timestamp 取出「小時數」，新增一個 Hour 欄位
df['Hour'] = df['Timestamp'].dt.hour
# 篩選出凌晨 0～6 點的流量紀錄
night_traffic = df[df['Hour'] < 6]
print(night_traffic[['Source IP', 'Destination IP', 'Timestamp']].head())


# In[10]:


# 統計每一種 Label 的出現次數
df['Label'].value_counts()


# In[14]:


# 找出封包數異常高的 flow
df[['Source IP', 'Destination IP', 'Total Fwd Packets', 'Total Backward Packets']].sort_values(by='Total Fwd Packets', ascending=False).head(10)


# In[15]:


df['Hour'] = df['Timestamp'].dt.hour
df.groupby(['Source IP', 'Hour']).size().unstack(fill_value=0).head(10)


# In[17]:


focus_ip = '10.42.0.211'

# 查它連過哪些不同的目標 IP
targets = df[df['Source IP'] == focus_ip]['Destination IP'].value_counts().head(10)
print(targets)


