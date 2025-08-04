import React, { useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card'
import { Badge } from './components/ui/badge'
import { Button } from './components/ui/button'
import { Toaster } from 'sonner'
import TrackingLinksPage from './components/TrackingLinksPage'
import LoginPage from './components/LoginPage'
import AdminPanel from './components/AdminPanel'
import Admin2Dashboard from './components/Admin2Dashboard'
import MemberDashboard from './components/MemberDashboard'
import WorkerDashboard from './components/WorkerDashboard'
import { API_ENDPOINTS } from './config'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Area, AreaChart
} from 'recharts'
import { 
  TrendingUp, Users, Globe, Shield, Activity, AlertTriangle,
  RefreshCw, Download, LogOut, Settings, Crown, Link
} from 'lucide-react'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [analytics, setAnalytics] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check for existing session
    const savedToken = localStorage.getItem('authToken')
    const savedUser = localStorage.getItem('user')
    
    if (savedToken && savedUser) {
      setToken(savedToken)
      setUser(JSON.parse(savedUser))
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    if (user && token) {
      fetchAnalytics()
      const interval = setInterval(fetchAnalytics, 30000) // Refresh every 30 seconds
      return () => clearInterval(interval)
    }
  }, [user, token])

  const fetchAnalytics = async () => {
    try {
      const response = await fetch(API_ENDPOINTS.ANALYTICS, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })
      if (response.ok) {
        const data = await response.json()
        setAnalytics(data)
      }
    } catch (error) {
      console.error('Failed to fetch analytics:', error)
    }
  }

  const handleLogin = (userData, authToken) => {
    setUser(userData)
    setToken(authToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('authToken')
    localStorage.removeItem('user')
    setUser(null)
    setToken(null)
    setAnalytics(null)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    )
  }

  if (!user || !token) {
    return (
      <>
        <LoginPage onLogin={handleLogin} />
        <Toaster />
      </>
    )
  }

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8']

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <Link className="h-8 w-8 text-blue-400" />
              <div>
                <h1 className="text-3xl font-bold text-white">Brain Link Tracker</h1>
                <p className="text-slate-300">Advanced Analytics Dashboard</p>
              </div>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <p className="text-white font-medium">{user.username}</p>
              <Badge className={`${getRoleBadgeColor(user.role)} text-white`}>
                {user.role === 'admin' && <Crown className="h-3 w-3 mr-1" />}
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </Badge>
            </div>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        {/* Main Content */}
        {user.role === 'member' ? (
          <MemberDashboard user={user} token={token} />
        ) : user.role === 'worker' ? (
          <WorkerDashboard user={user} token={token} />
        ) : (
          <div className="bg-white rounded-lg shadow-lg">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <h2 className="text-2xl font-bold text-gray-800">Advanced Analytics</h2>
                  <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                    Last updated: {analytics ? new Date().toLocaleTimeString() : 'Loading...'}
                  </Badge>
                </div>
                <div className="flex space-x-2">
                  <Button variant="outline" size="sm" onClick={fetchAnalytics}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                  <Button variant="outline" size="sm">
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </Button>
                  <Button variant="outline" size="sm">
                    <Settings className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <Tabs defaultValue="analytics" className="w-full">
                <TabsList className="grid w-full grid-cols-6">
                  <TabsTrigger value="analytics">Analytics</TabsTrigger>
                  <TabsTrigger value="tracking-links">Tracking Links</TabsTrigger>
                  {(user.role === 'admin' || user.role === 'admin2') && (
                    <TabsTrigger value="admin">
                      {user.role === 'admin' ? 'User Management' : 'Team Management'}
                    </TabsTrigger>
                  )}
                  <TabsTrigger value="security">Security</TabsTrigger>
                  <TabsTrigger value="geography">Geography</TabsTrigger>
                  <TabsTrigger value="live-activity">Live Activity</TabsTrigger>
                </TabsList>

              <TabsContent value="analytics" className="space-y-6">
                {analytics && (
                  <>
                    {/* Overview Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <TrendingUp className="h-5 w-5 text-blue-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Total Clicks</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.overview.totalClicks}</p>
                              <p className="text-xs text-green-600">+12.5% from last week</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <div className="h-5 w-5 bg-green-500 rounded-full flex items-center justify-center">
                              <span className="text-white text-xs">@</span>
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-600">Email Opens</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.overview.totalOpens}</p>
                              <p className="text-xs text-green-600">+8.2% from last week</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Users className="h-5 w-5 text-purple-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Unique Visitors</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.overview.uniqueVisitors}</p>
                              <p className="text-xs text-green-600">+5.7% from last week</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Activity className="h-5 w-5 text-orange-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Conversion Rate</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.overview.conversionRate}%</p>
                              <p className="text-xs text-green-600">+2.1% from last week</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <Shield className="h-5 w-5 text-red-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Blocked Requests</p>
                              <p className="text-2xl font-bold text-gray-900">{analytics.overview.blockedRequests}</p>
                              <p className="text-xs text-red-600">Security active</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardContent className="p-4">
                          <div className="flex items-center space-x-2">
                            <AlertTriangle className="h-5 w-5 text-yellow-500" />
                            <div>
                              <p className="text-sm font-medium text-gray-600">Risk Score</p>
                              <p className="text-2xl font-bold text-gray-900">{(analytics.overview.riskScore * 100).toFixed(1)}%</p>
                              <p className="text-xs text-yellow-600">Monitoring</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle>Hourly Activity (Last 24 Hours)</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ResponsiveContainer width="100%" height={300}>
                            <AreaChart data={analytics.hourlyActivity}>
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="hour" />
                              <YAxis />
                              <Tooltip />
                              <Area type="monotone" dataKey="clicks" stackId="1" stroke="#8884d8" fill="#8884d8" />
                              <Area type="monotone" dataKey="opens" stackId="1" stroke="#82ca9d" fill="#82ca9d" />
                            </AreaChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle>Device Types</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ResponsiveContainer width="100%" height={300}>
                            <PieChart>
                              <Pie
                                data={analytics.deviceTypes}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, value }) => `${name}: ${value}%`}
                                outerRadius={80}
                                fill="#8884d8"
                                dataKey="value"
                              >
                                {analytics.deviceTypes.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                              </Pie>
                              <Tooltip />
                            </PieChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>
                    </div>
                  </>
                )}
              </TabsContent>

              <TabsContent value="tracking-links">
                <TrackingLinksPage user={user} token={token} />
              </TabsContent>

              {(user.role === 'admin' || user.role === 'admin2') && (
                <TabsContent value="admin">
                  {user.role === 'admin' ? (
                    <AdminPanel user={user} token={token} />
                  ) : (
                    <Admin2Dashboard user={user} token={token} />
                  )}
                </TabsContent>
              )}

              <TabsContent value="security" className="space-y-6">
                {analytics && (
                  <>
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center space-x-2">
                          <Shield className="h-5 w-5" />
                          <span>Security Events</span>
                        </CardTitle>
                        <CardDescription>
                          Real-time security monitoring and threat detection
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                          {analytics.securityEvents.map((event, index) => (
                            <Card key={index}>
                              <CardContent className="p-4">
                                <div className="flex items-center justify-between">
                                  <div>
                                    <p className="text-sm font-medium text-gray-600">{event.type}</p>
                                    <p className="text-2xl font-bold text-gray-900">{event.count}</p>
                                  </div>
                                  <Badge variant={event.severity === 'high' ? 'destructive' : 'secondary'}>
                                    {event.severity}
                                  </Badge>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </TabsContent>

              <TabsContent value="geography" className="space-y-6">
                {analytics && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center space-x-2">
                        <Globe className="h-5 w-5" />
                        <span>Top Countries</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {analytics.topCountries.map((country, index) => (
                          <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                                {country.code}
                              </div>
                              <div>
                                <p className="font-medium">{country.country}</p>
                                <p className="text-sm text-gray-600">{country.clicks} clicks, {country.opens} opens</p>
                              </div>
                            </div>
                            <Badge variant="outline">{country.percentage}%</Badge>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="live-activity" className="space-y-6">
                {analytics && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center space-x-2">
                        <Activity className="h-5 w-5" />
                        <span>Recent Activity</span>
                      </CardTitle>
                      <CardDescription>
                        Live tracking events and user interactions
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {analytics.recentActivity.map((activity, index) => (
                          <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                            <div className="flex items-center space-x-3">
                              <div className={`w-3 h-3 rounded-full ${activity.status === 'success' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                              <div>
                                <p className="font-medium">{activity.event}</p>
                                <p className="text-sm text-gray-600">{activity.location} • {activity.device}</p>
                              </div>
                            </div>
                            <div className="text-right">
                              <p className="text-sm text-gray-600">{activity.time}</p>
                              <Badge variant={activity.status === 'success' ? 'default' : 'destructive'}>
                                {activity.status}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>
            </Tabs>
          </div>
        </div>
        )}
      </div>
      <Toaster />
    </div>
  )
}

function getRoleBadgeColor(role) {
  switch (role) {
    case 'admin': return 'bg-red-500'
    case 'admin2': return 'bg-orange-500'
    case 'member': return 'bg-blue-500'
    case 'worker': return 'bg-green-500'
    default: return 'bg-gray-500'
  }
}

export default App

