import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import fromUnixTime from 'date-fns/fromUnixTime';
import PropTypes from 'prop-types';
import React from 'react';

const Timestamp = function ({
  timestamp,
  expiration = false,
  className = undefined,
}) {
  if (!timestamp) return <em className={className}>never</em>;
  const date = fromUnixTime(timestamp);
  const absolute = date.toISOString().replace(/\.0+Z$/, 'Z');
  if (expiration && date < new Date()) {
    return (
      <time title={absolute} dateTime={absolute} className={className}>
        expired
      </time>
    );
  }
  const relative = formatDistanceToNow(date, { addSuffix: !expiration });
  return (
    <time title={absolute} dateTime={absolute} className={className}>
      {relative}
    </time>
  );
};
Timestamp.propTypes = {
  timestamp: PropTypes.number.isRequired,
  expiration: PropTypes.bool,
  className: PropTypes.string,
};

export default Timestamp;
