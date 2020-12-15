import { useCallback, useState } from 'react';

export default function useError() {
  const [error, setError] = useState(null);

  const onError = useCallback(
    (error) => {
      if (error instanceof TypeError) {
        setError('Unable to contact backend API');
      } else if (error && error.stack && error.message) {
        setError(error.message);
      } else {
        setError(error);
      }
    },
    [setError]
  );

  return { error, onError };
}
