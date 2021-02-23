import { useState, useEffect } from 'react';
import { apiGet } from '../functions/api';

export default function useFetch(uri, alert) {
  const [data, setData] = useState();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!uri) return;
    apiGet(uri)
      .then(setData)
      .then(() => setLoading(false))
      .catch((e) => alert.show(e.message));
  }, [alert, uri]);

  return { loading, data };
}
