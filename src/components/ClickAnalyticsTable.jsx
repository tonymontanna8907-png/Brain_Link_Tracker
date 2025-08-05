import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Badge } from './ui/badge';
import { 
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from './ui/table';
import { 
  Activity, RefreshCw, Search, Globe, Monitor, 
  Smartphone, MapPin, Wifi, Clock, Link
} from 'lucide-react';
import { toast } from 'sonner';
import { API_ENDPOINTS } from '../config';

const ClickAnalyticsTable = ({ token }) => {
  const [clickData, setClickData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchClickAnalytics = async () => {
    try {
      setLoading(true);
      const response = await fetch(API_ENDPOINTS.CLICK_ANALYTICS, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setClickData(data.clicks || []);
      } else {
        toast.error('Failed to fetch click analytics');
      }
    } catch (error) {
      console.error('Error fetching click analytics:', error);
      toast.error('Network error while fetching click analytics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchClickAnalytics();
  }, [token]);

  const filteredClicks = clickData.filter(click =>
    click.tracking_token?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    click.campaign_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    click.ip_address?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    click.country?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return 'Invalid Date';
    }
  };

  const getDeviceIcon = (userAgent) => {
    if (!userAgent) return <Monitor className="h-4 w-4" />;
    const ua = userAgent.toLowerCase();
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
      return <Smartphone className="h-4 w-4" />;
    }
    return <Monitor className="h-4 w-4" />;
  };

  const truncateUserAgent = (userAgent) => {
    if (!userAgent) return 'Unknown';
    return userAgent.length > 50 ? userAgent.substring(0, 50) + '...' : userAgent;
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Activity className="h-5 w-5" />
            <span>Recent Activity</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32">
            <div className="text-muted-foreground">Loading click analytics...</div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Recent Activity</span>
            </CardTitle>
            <CardDescription>
              Detailed click analytics and visitor information
            </CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search clicks..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 w-64"
              />
            </div>
            <Button variant="outline" size="sm" onClick={fetchClickAnalytics}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tracking ID</TableHead>
                <TableHead>Campaign</TableHead>
                <TableHead>IP Address</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Device/Browser</TableHead>
                <TableHead>ISP</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>User Agent</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredClicks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    {searchTerm ? 'No clicks match your search.' : 'No click data available yet.'}
                  </TableCell>
                </TableRow>
              ) : (
                filteredClicks.map((click, index) => (
                  <TableRow key={`${click.tracking_token}-${index}`}>
                    <TableCell className="font-mono text-sm">
                      <div className="flex items-center space-x-2">
                        <Link className="h-4 w-4 text-blue-500" />
                        <span>{click.tracking_token}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {click.campaign_name}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {click.ip_address || 'N/A'}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-1">
                        <MapPin className="h-4 w-4 text-green-500" />
                        <span className="text-sm">
                          {click.country}
                          {click.state && click.state !== 'Private' && `, ${click.state}`}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        {getDeviceIcon(click.user_agent)}
                        <div className="text-sm">
                          <div>{click.browser}</div>
                          <div className="text-xs text-muted-foreground">{click.os}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-1">
                        <Wifi className="h-4 w-4 text-purple-500" />
                        <span className="text-sm">{click.isp}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-1">
                        <Clock className="h-4 w-4 text-gray-500" />
                        <span className="text-sm">{formatTimestamp(click.timestamp)}</span>
                      </div>
                    </TableCell>
                    <TableCell className="max-w-xs">
                      <div className="text-xs text-muted-foreground" title={click.user_agent}>
                        {truncateUserAgent(click.user_agent)}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
        {filteredClicks.length > 0 && (
          <div className="mt-4 text-sm text-muted-foreground">
            Showing {filteredClicks.length} of {clickData.length} clicks
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ClickAnalyticsTable;

